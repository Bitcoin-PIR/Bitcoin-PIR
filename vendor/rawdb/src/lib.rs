#![doc = include_str!("../README.md")]

use std::{
    collections::HashSet,
    fmt,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    sync::{
        Arc, Weak,
        atomic::{AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use log::{debug, trace};
use memmap2::MmapMut;
use parking_lot::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

mod disk_usage;
pub mod error;
mod hints;
mod hole_punch;
mod layout;
mod mmap;
mod reader;
mod region;
mod region_metadata;
mod region_state;
mod regions;

pub use disk_usage::*;
pub use error::*;
pub use hints::*;
use hole_punch::*;
use layout::*;
use mmap::*;
use rayon::prelude::*;
pub use reader::*;
pub use region::*;
pub use region_metadata::*;
use region_state::*;
use regions::*;

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SIZE_MINUS_1: usize = PAGE_SIZE - 1;
/// One gibibyte (1024^3 bytes).
#[allow(non_upper_case_globals)]
pub const GiB: usize = 1024 * 1024 * 1024;

/// Memory-mapped database with region-based storage and hole punching.
#[derive(Clone)]
#[must_use = "Database should be stored to keep the database open"]
pub struct Database(Arc<DatabaseInner>);

/// Lock ordering: layout → regions → mmap → file → meta → dirty_bounds.
struct DatabaseInner {
    path: PathBuf,
    name: String,
    layout: RwLock<Layout>,
    regions: RwLock<Regions>,
    mmap: RwLock<MmapMut>,
    file: RwLock<File>,
    cached_file_len: AtomicUsize,
    bg_tasks: Mutex<Vec<JoinHandle<Result<()>>>>,
}

impl Database {
    /// Opens or creates a database at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_min_len(path, 0)
    }

    pub fn open_with_min_len(path: &Path, min_len: usize) -> Result<Self> {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        fs::create_dir_all(path)?;

        let file = OpenOptions::new()
            .read(true)
            .create(true)
            .write(true)
            .truncate(false)
            .open(Self::data_path_from(path))?;

        file.try_lock()?;

        let mut file_len = file.metadata()?.len() as usize;
        if file_len < min_len {
            file.set_len(min_len as u64)?;
            file.sync_all()?;
            file_len = min_len;
        }

        let regions = Regions::open(path)?;
        let mmap = create_mmap(&file)?;

        let db = Self(Arc::new(DatabaseInner {
            path: path.to_owned(),
            name,
            layout: RwLock::new(Layout::default()),
            regions: RwLock::new(regions),
            mmap: RwLock::new(mmap),
            file: RwLock::new(file),
            cached_file_len: AtomicUsize::new(file_len),
            bg_tasks: Mutex::new(Vec::new()),
        }));

        db.regions_mut().fill(&db)?;
        *db.layout_mut() = Layout::from(&*db.regions());

        debug!("{}: opened with {} regions", db, db.regions().len());

        Ok(db)
    }

    /// Cached file length (no syscall).
    #[inline]
    pub fn file_len(&self) -> usize {
        self.0.cached_file_len.load(Ordering::Relaxed)
    }

    /// Grows the file if needed (doubles size, 1 MiB floor, sparse-file friendly).
    pub fn set_min_len(&self, len: usize) -> Result<()> {
        let len = Self::ceil_number_to_page_size_multiple(len);

        if self.file_len() >= len {
            return Ok(());
        }

        trace!("{}: set_min_len acquiring mmap_mut", self);
        let mut mmap = self.mmap_mut();
        trace!("{}: set_min_len acquiring file_mut", self);
        let file = self.file_mut();

        // Re-check after acquiring lock (another thread may have grown the file).
        let current_len = self.file_len();
        if current_len >= len {
            return Ok(());
        }

        let target_len = Self::ceil_number_to_page_size_multiple(
            len.max(current_len * 2).max(1024 * 1024),
        );
        debug!("{}: set_min_len to {} (requested {})", self, target_len, len);
        file.set_len(target_len as u64)?;
        self.0.cached_file_len.store(target_len, Ordering::Relaxed);
        *mmap = create_mmap(&file)?;
        Ok(())
    }

    pub fn set_min_regions(&self, regions: usize) -> Result<()> {
        self.regions_mut()
            .set_min_len(regions * SIZE_OF_REGION_METADATA)?;
        self.set_min_len(regions * PAGE_SIZE)
    }

    pub fn get_region(&self, id: &str) -> Option<Region> {
        self.regions().get_from_id(id).cloned()
    }

    pub fn create_region_if_needed(&self, id: &str) -> Result<Region> {
        if let Some(region) = self.get_region(id) {
            return Ok(region);
        }

        let layout = self.layout();
        if layout.find_smallest_adequate_hole(PAGE_SIZE).is_none() {
            let end = layout.len();
            drop(layout);
            self.set_min_len(end + PAGE_SIZE)?;
        } else {
            drop(layout);
        }

        debug!("{}: create_region_if_needed '{}'", self, id);
        trace!(
            "{}: create_region_if_needed '{}' acquiring layout_mut",
            self, id
        );
        let mut layout = self.layout_mut();
        trace!(
            "{}: create_region_if_needed '{}' acquiring regions_mut",
            self, id
        );
        let mut regions = self.regions_mut();

        if let Some(region) = regions.get_from_id(id).cloned() {
            return Ok(region);
        }

        let start = if let Some(start) = layout.find_smallest_adequate_hole(PAGE_SIZE) {
            layout.remove_or_compress_hole(start, PAGE_SIZE)?;
            start
        } else {
            layout.len()
        };

        let region = regions.create(self, id.to_owned(), start)?;
        layout.insert_region(start, &region);
        Ok(region)
    }

    #[inline]
    pub(crate) fn write(&self, start: usize, data: &[u8]) {
        write_to_mmap(&self.mmap(), start, data);
    }

    pub(crate) fn copy(&self, src: usize, dst: usize, len: usize) -> Result<()> {
        if len == 0 {
            return Ok(());
        }

        let src_end = src + len;
        let dst_end = dst + len;
        if !(src_end <= dst || dst_end <= src) {
            return Err(Error::OverlappingCopyRanges {
                src,
                src_end,
                dst,
                dst_end,
            });
        }

        let mmap = self.mmap();
        write_to_mmap(&mmap, dst, &mmap[src..src_end]);
        Ok(())
    }

    pub fn remove_region_if_exists(&self, id: &str) -> Result<()> {
        match self.remove_region(id) {
            Ok(()) | Err(Error::RegionNotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn remove_region(&self, id: &str) -> Result<()> {
        let Some(region) = self.get_region(id) else {
            return Err(Error::RegionNotFound);
        };
        region.remove()
    }

    /// Removes all regions except those in `ids`.
    pub fn retain_regions(&self, mut ids: HashSet<String>) -> Result<()> {
        debug!(
            "{}: retain_regions called with {} ids to keep",
            self,
            ids.len()
        );

        let regions = self.regions();
        let regions_to_remove: Vec<_> = regions
            .id_to_index()
            .keys()
            .filter(|id| !ids.remove(&**id))
            .filter_map(|id| regions.get_from_id(id).cloned())
            .collect();
        drop(regions);

        if !ids.is_empty() {
            debug!(
                "{}: retain_regions: {} ids in retain set not found in db: {:?}",
                self,
                ids.len(),
                ids
            );
        }

        if !regions_to_remove.is_empty() {
            debug!(
                "{}: retain_regions removing {} regions: {:?}",
                self,
                regions_to_remove.len(),
                regions_to_remove
                    .iter()
                    .map(|r| r.meta().id().to_string())
                    .collect::<Vec<_>>()
            );
        }

        for region in regions_to_remove {
            let ref_count = std::sync::Arc::strong_count(region.arc());
            debug!(
                "{}: removing '{}' (arc count: {})",
                self,
                region.meta().id(),
                ref_count
            );
            region.remove()?;
        }
        Ok(())
    }

    /// Opens the data file read-only (for external consumers like mmap readers).
    #[inline]
    pub fn open_read_only_file(&self) -> Result<File> {
        File::open(self.data_path()).map_err(Error::from)
    }

    pub fn disk_usage(&self) -> Result<DiskUsage> {
        DiskUsage::from_file(&self.file())
    }

    /// Flushes all dirty data and metadata to disk. Returns number of flushed regions.
    pub fn flush(&self) -> Result<usize> {
        let dirty_regions: Vec<(Region, Option<(usize, usize)>)> = self
            .regions()
            .index_to_region()
            .iter()
            .flatten()
            .filter_map(|r| {
                let bounds = r.take_dirty_bounds();
                if bounds.is_some() || r.meta().needs_flush() {
                    Some((r.clone(), bounds))
                } else {
                    None
                }
            })
            .collect();

        if dirty_regions.is_empty() {
            debug!("{}: flush (no dirty)", self);
            self.layout_mut().promote_pending_holes(self.name());
            return Ok(0);
        }

        let (flush_start, flush_end) = dirty_regions
            .iter()
            .filter_map(|(r, bounds)| {
                let (min, max) = (*bounds)?;
                let region_start = r.meta().start();
                Some((region_start + min, region_start + max))
            })
            .fold((usize::MAX, 0usize), |(min_s, max_e), (s, e)| {
                (min_s.min(s), max_e.max(e))
            });

        if flush_start < flush_end {
            let mmap = self.mmap();
            if let Err(e) = mmap.flush_async_range(flush_start, flush_end - flush_start) {
                drop(mmap);
                for (region, bounds) in dirty_regions {
                    if let Some((min, max)) = bounds {
                        region.restore_dirty_bounds(min, max);
                    }
                }
                return Err(e.into());
            }
        }

        // Data must be durable before metadata (crash safety).
        self.regions().flush()?;
        self.file().sync_data()?;
        self.regions().sync_data()?;
        for (region, _) in &dirty_regions {
            region.meta().mark_clean();
        }

        debug!("{}: flushed {} regions", self, dirty_regions.len());
        self.layout_mut().promote_pending_holes(self.name());
        Ok(dirty_regions.len())
    }

    /// Gives the OS time to write dirty mmap pages before fsyncing.
    /// Intended for background tasks where the delay is invisible.
    pub fn compact_deferred(&self, delay: Duration) -> Result<()> {
        thread::sleep(delay);
        self.compact()
    }

    /// Like `compact_deferred` with a 5-second default delay.
    pub fn compact_deferred_default(&self) -> Result<()> {
        self.compact_deferred(Duration::from_secs(5))
    }

    /// Flushes, then punches holes to reclaim disk space.
    #[inline]
    pub fn compact(&self) -> Result<()> {
        let i = Instant::now();
        self.flush()?;
        let flush_time = i.elapsed();
        let i = Instant::now();
        let r = self.punch_holes();
        let punch_time = i.elapsed();
        debug!(
            "{}: compact in {:?} (flush: {:?}, punch_holes: {:?})",
            self,
            flush_time + punch_time,
            flush_time,
            punch_time
        );
        r
    }

    /// Runs `f` on a background thread without incrementing the Arc refcount,
    /// so `strong_count` reflects only real owners.
    /// Call `sync_bg_tasks()` before the next write to this database.
    pub fn run_bg(&self, f: impl FnOnce(&Self) -> Result<()> + Send + 'static) {
        use std::mem::ManuallyDrop;
        // Safety: sync_bg_tasks (called explicitly or from Drop at strong_count == 1)
        // joins this thread before the Arc is deallocated.
        // ManuallyDrop prevents the refcount decrement we never incremented.
        let db = ManuallyDrop::new(unsafe { Self(Arc::from_raw(Arc::as_ptr(&self.0))) });
        self.0.bg_tasks.lock().push(thread::spawn(move || f(&db)));
    }

    /// Joins all pending background tasks on this database.
    pub fn sync_bg_tasks(&self) -> Result<()> {
        let handles: Vec<_> = self.0.bg_tasks.lock().drain(..).collect();
        for handle in handles {
            handle.join().unwrap()?;
        }
        Ok(())
    }

    fn punch_holes(&self) -> Result<()> {
        let layout = self.layout();

        let regions_to_check: Vec<Region> = {
            let regions = self.regions();
            regions
                .index_to_region()
                .iter()
                .flatten()
                .cloned()
                .collect()
        };

        // Collect layout holes (protected by layout READ - can punch in parallel)
        let layout_holes: Vec<(usize, usize)> = layout
            .start_to_hole()
            .iter()
            .map(|(&start, &hole)| (start, hole))
            .collect();

        let file = self.file();
        let mut punched = 0usize;

        // Punch region reserved space. We MUST hold meta WRITE before checking,
        // because write_with does db.write() BEFORE updating meta. If we only
        // acquire WRITE after checking, a concurrent write could be in progress.
        for region in &regions_to_check {
            let meta = region.meta_mut();
            let rstart = meta.start();
            let len = meta.len();
            let reserved = meta.reserved();
            let ceil_len = Self::ceil_number_to_page_size_multiple(len);

            if ceil_len < reserved {
                let start = rstart + ceil_len;
                let hole = reserved - ceil_len;
                if Self::approx_has_punchable_data(&file, start, hole) {
                    HolePunch::punch(&file, start, hole)?;
                    punched += 1;
                }
            }
        }

        // Punch layout holes in parallel (safe - layout READ prevents allocation)
        // No per-region lock needed since these are unallocated holes.
        let layout_punched: usize = layout_holes
            .par_iter()
            .filter_map(|&(start, hole)| {
                if Self::approx_has_punchable_data(&file, start, hole) {
                    HolePunch::punch(&file, start, hole).ok()?;
                    Some(1)
                } else {
                    None
                }
            })
            .sum();
        punched += layout_punched;

        drop(file);
        drop(layout);

        // No mmap recreation needed: KEEP_SIZE preserves file length, kernel zeroes punched pages.
        if punched > 0 {
            debug!("{}: punch_holes syncing after {} punches", self, punched);
            let file = self.file();
            file.sync_data()?;
        }

        Ok(())
    }

    /// Samples a few bytes via pread to check if a hole has non-zero data.
    fn approx_has_punchable_data(file: &File, start: usize, len: usize) -> bool {
        use std::os::unix::io::AsRawFd;

        assert!(start.is_multiple_of(PAGE_SIZE));
        assert!(len.is_multiple_of(PAGE_SIZE));

        let fd = file.as_raw_fd();
        let mut buf = [0u8; 1];

        let mut check_page = |page_start: usize| -> bool {
            let n = unsafe {
                libc::pread(
                    fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    1,
                    page_start as libc::off_t,
                )
            };
            if n == 1 && buf[0] != 0 {
                return true;
            }

            let page_end = page_start + PAGE_SIZE - 1;
            let n = unsafe {
                libc::pread(
                    fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    1,
                    page_end as libc::off_t,
                )
            };
            n == 1 && buf[0] != 0
        };

        if check_page(start) {
            return true;
        }

        let last_page_start = start + len - PAGE_SIZE;
        if last_page_start != start && check_page(last_page_start) {
            return true;
        }

        if len > GiB {
            let num_gb_checks = len / GiB;
            for i in 1..num_gb_checks {
                let gb_boundary = start + i * GiB;
                if check_page(gb_boundary) {
                    return true;
                }
            }
        }

        false
    }

    #[inline(always)]
    pub fn file(&self) -> RwLockReadGuard<'_, File> {
        self.0.file.read()
    }

    #[inline(always)]
    pub fn file_mut(&self) -> RwLockWriteGuard<'_, File> {
        self.0.file.write()
    }

    #[inline(always)]
    pub fn mmap(&self) -> RwLockReadGuard<'_, MmapMut> {
        self.0.mmap.read()
    }

    #[inline(always)]
    pub fn mmap_mut(&self) -> RwLockWriteGuard<'_, MmapMut> {
        self.0.mmap.write()
    }

    #[inline(always)]
    pub fn regions(&self) -> RwLockReadGuard<'_, Regions> {
        self.0.regions.read()
    }

    #[inline(always)]
    pub(crate) fn regions_mut(&self) -> RwLockWriteGuard<'_, Regions> {
        self.0.regions.write()
    }

    #[inline(always)]
    pub fn layout(&self) -> RwLockReadGuard<'_, Layout> {
        self.0.layout.read()
    }

    #[inline(always)]
    pub(crate) fn layout_mut(&self) -> RwLockWriteGuard<'_, Layout> {
        self.0.layout.write()
    }

    #[inline]
    fn ceil_number_to_page_size_multiple(num: usize) -> usize {
        (num + PAGE_SIZE_MINUS_1) & !PAGE_SIZE_MINUS_1
    }

    #[inline(always)]
    fn data_path(&self) -> PathBuf {
        Self::data_path_from(self.path())
    }
    #[inline(always)]
    fn data_path_from(path: &Path) -> PathBuf {
        path.join("data")
    }

    #[inline(always)]
    pub fn path(&self) -> &Path {
        &self.0.path
    }

    #[inline]
    pub fn weak_clone(&self) -> WeakDatabase {
        WeakDatabase(Arc::downgrade(&self.0))
    }

    #[inline]
    pub fn name(&self) -> &str {
        &self.0.name
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        if Arc::strong_count(&self.0) == 1 {
            let _ = self.sync_bg_tasks();
        }
    }
}

impl fmt::Display for Database {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Weak reference to a [`Database`], held by regions to avoid reference cycles.
#[derive(Debug, Clone)]
pub struct WeakDatabase(Weak<DatabaseInner>);

impl WeakDatabase {
    pub fn upgrade(&self) -> Database {
        Database(
            self.0
                .upgrade()
                .expect("Database was dropped while Region still exists"),
        )
    }
}
