"""
Qt GUI for PIR Privacy plugin — settings dialog and status display.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QComboBox, QSpinBox, QPushButton,
    QGroupBox, QFrame,
)
from PyQt6.QtCore import Qt

from electrum.i18n import _
from electrum.gui.qt.util import WindowModalDialog, Buttons, OkButton, CancelButton

from .pir_plugin import PirPrivacyPlugin

if TYPE_CHECKING:
    from electrum.gui.qt.main_window import ElectrumWindow

# Default server URLs per protocol
_PROTOCOL_DEFAULTS = {
    0: {  # DPF
        'label0': _('Server 0 URL:'),
        'label1': _('Server 1 URL:'),
        'url0': 'ws://localhost:8091',
        'url1': 'ws://localhost:8092',
    },
    1: {  # HarmonyPIR
        'label0': _('Hint Server URL:'),
        'label1': _('Query Server URL:'),
        'url0': 'ws://localhost:8094',
        'url1': 'ws://localhost:8095',
    },
    2: {  # OnionPIR
        'label0': _('Server URL:'),
        'label1': '',
        'url0': 'ws://localhost:8093',
        'url1': '',
    },
}


class Plugin(PirPrivacyPlugin):
    """Qt-specific plugin class with settings UI."""

    def requires_settings(self) -> bool:
        return True

    def settings_dialog(self, window, wallet):
        """Show settings dialog (Electrum 4.7 plugin API)."""
        d = WindowModalDialog(window, _('PIR Privacy Settings'))
        layout = QVBoxLayout(d)

        # ── Protocol selection ─────────────────────────────────────────
        protocol_group = QGroupBox(_('PIR Protocol'))
        protocol_layout = QGridLayout()

        protocol_layout.addWidget(QLabel(_('Protocol:')), 0, 0)
        protocol_combo = QComboBox()
        protocol_combo.addItems([
            'DPF 2-Server (recommended)',
            'HarmonyPIR 2-Server',
            'OnionPIRv2 1-Server',
        ])
        protocol_map = {'dpf': 0, 'harmony': 1, 'onionpir': 2}
        protocol_combo.setCurrentIndex(protocol_map.get(self.pir_protocol, 0))
        protocol_layout.addWidget(protocol_combo, 0, 1)

        # HarmonyPIR PRP backend (only visible when HarmonyPIR selected)
        prp_label = QLabel(_('PRP Backend:'))
        protocol_layout.addWidget(prp_label, 1, 0)
        prp_combo = QComboBox()
        prp_combo.addItems([
            'Hoang (default)',
            'FastPRP',
            'ALF',
        ])
        prp_combo.setCurrentIndex(self.prp_backend)
        protocol_layout.addWidget(prp_combo, 1, 1)

        protocol_group.setLayout(protocol_layout)
        layout.addWidget(protocol_group)

        # ── Server URLs ────────────────────────────────────────────────
        server_group = QGroupBox(_('Server Configuration'))
        server_layout = QGridLayout()

        server0_label = QLabel()
        server_layout.addWidget(server0_label, 0, 0)
        server0_input = QLineEdit()
        server_layout.addWidget(server0_input, 0, 1)

        server1_label = QLabel()
        server_layout.addWidget(server1_label, 1, 0)
        server1_input = QLineEdit()
        server_layout.addWidget(server1_input, 1, 1)

        def _on_protocol_changed(idx):
            defaults = _PROTOCOL_DEFAULTS.get(idx, _PROTOCOL_DEFAULTS[0])
            server0_label.setText(defaults['label0'])
            server0_input.setText(defaults['url0'])
            server1_label.setText(defaults['label1'])
            server1_input.setText(defaults['url1'])
            server1_label.setVisible(bool(defaults['label1']))
            server1_input.setVisible(bool(defaults['url1']))
            # PRP backend only relevant for HarmonyPIR
            is_harmony = (idx == 1)
            prp_label.setVisible(is_harmony)
            prp_combo.setVisible(is_harmony)

        protocol_combo.currentIndexChanged.connect(_on_protocol_changed)
        # Initialize with current selection
        _on_protocol_changed(protocol_combo.currentIndex())

        server_group.setLayout(server_layout)
        layout.addWidget(server_group)

        # ── Sync settings ──────────────────────────────────────────────
        sync_group = QGroupBox(_('Synchronization'))
        sync_layout = QGridLayout()

        sync_layout.addWidget(QLabel(_('Poll interval (seconds):')), 0, 0)
        interval_spin = QSpinBox()
        interval_spin.setRange(5, 300)
        interval_spin.setValue(self.sync_interval)
        sync_layout.addWidget(interval_spin, 0, 1)

        sync_group.setLayout(sync_layout)
        layout.addWidget(sync_group)

        # ── Status display ─────────────────────────────────────────────
        status_group = QGroupBox(_('Status'))
        status_layout = QVBoxLayout()
        self._status_label = QLabel(_('Not synced yet'))
        self._status_label.setWordWrap(True)
        status_layout.addWidget(self._status_label)

        refresh_btn = QPushButton(_('Refresh Status'))
        refresh_btn.clicked.connect(self._update_status_display)
        status_layout.addWidget(refresh_btn)

        status_group.setLayout(status_layout)
        layout.addWidget(status_group)

        # ── Dialog buttons ────────────────────────────────────────────
        layout.addLayout(Buttons(OkButton(d), CancelButton(d)))

        self._update_status_display()

        if not d.exec():
            return

        # Apply settings on OK
        idx_to_proto = {0: 'dpf', 1: 'harmony', 2: 'onionpir'}
        self.update_settings({
            'protocol': idx_to_proto.get(protocol_combo.currentIndex(), 'dpf'),
            'server0_url': server0_input.text().strip(),
            'server1_url': server1_input.text().strip(),
            'sync_interval': interval_spin.value(),
            'prp_backend': prp_combo.currentIndex(),
        })

    def _update_status_display(self):
        """Update the status label with current sync info."""
        lines = []

        if not self._synchronizers:
            lines.append(_('No wallets loaded'))
        else:
            for wallet_id, sync in self._synchronizers.items():
                status = sync.get_status()
                lines.append(f"Wallet: {wallet_id[:8]}...")
                lines.append(f"  Running: {'Yes' if status['running'] else 'No'}")
                lines.append(f"  Addresses: {status['total_addresses']}")
                lines.append(f"  With UTXOs: {status['addresses_with_utxos']}")
                lines.append(f"  Total UTXOs: {status['total_utxos']}")
                btc = status['total_sats'] / 1e8
                lines.append(f"  Balance: {status['total_sats']} sats ({btc:.8f} BTC)")

                if status['last_sync'] > 0:
                    ago = time.time() - status['last_sync']
                    lines.append(f"  Last sync: {ago:.0f}s ago")
                else:
                    lines.append("  Last sync: never")

        if self._pir_client:
            lines.append('')
            lines.append(f"PIR Protocol: {self.pir_protocol}")
            lines.append(f"Connected: {'Yes' if self._pir_client.is_connected else 'No'}")
            if self._pir_client.index_bins > 0:
                lines.append(f"Index bins: {self._pir_client.index_bins:,}")
                lines.append(f"Chunk bins: {self._pir_client.chunk_bins:,}")

        self._status_label.setText('\n'.join(lines) if lines else _('Initializing...'))
