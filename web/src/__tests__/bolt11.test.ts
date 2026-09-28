import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { decodeBolt11 } from '../bolt11.js';

/** The x402 lnbtc specification's sample invoice (secp256k1 key 1). */
const SPEC_INVOICE =
  'lnbc250n1pj48ugqpp54y3u9s8ylemsv8l3ewyzzu0klhujvuvmkl6llchq23vy8rzjsf0qsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp5p4nz8am4uqj4q8a87z3sk4x6yk4dv2mvel34epw68qqkwy0xcqvqxqzfvcqpjr4rx6ls6j5rpwknuea64evlk7yfx56wmqcer5eerekdsn9tlv6v4ex9mlz5dtm9qapl3svwlqcf7837dmjkru9z9w4h2rvm0md52w2sqxrwu5f';
const KEY_ONE = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
/** Signed by the issuer test helper (key 1) for the fixed x402 test body. */
export const FIXTURE_INVOICE =
  'lnbc400n1p45n5sqpp5gf0dfe9rdvcw5gdepcsuwykxf85zznpfkl40dqyf6ypecmj48pxqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9qrsgqxqzuycqpjhp5q7quqs3pkr224sru5guwmyn68qpm6yl0vcttxzkd6tdn0m0y8w6se06vld3cdm8p040y6d8gl333jsa3r2d7tt6jng4p3uhc5lrxsne5krv4wwvl3slptxmuxm62ucmclyrku6wsvrzdq5lvqfx7y92j48gqv74dcl';
export const FIXTURE_REQUEST_HASH = '0781c04221b0d4aac07ca238ed927a3803bd13ef6616b30acdd2db37ede43bb5';
export const FIXTURE_PREIMAGE = '42'.repeat(32);
export const FIXTURE_PAYMENT_HASH = '425ed4e4a36b30ea21b90e21c712c649e8214c29b7eaf68089d1039c6e55384c';

describe('decodeBolt11', () => {
  it('decodes the specification sample and recovers its payee', () => {
    const d = decodeBolt11(SPEC_INVOICE);
    expect(d.currency).toBe('bc');
    expect(d.amountMsat).toBe(25_000n);
    expect(d.timestamp).toBe(1_700_000_000);
    expect(d.expirySecs).toBe(300);
    expect(d.description).toBeNull();
    expect(d.descriptionHashHex).toBe('0d6623f775e025501fa7f0a30b54da25aad62b6ccfe35c85da38016711e6c018');
    expect(d.payeeHex).toBe(KEY_ONE);
    expect(d.payeeFromField).toBe(false);
    const preimage = Buffer.from('0001020304050607080900010203040506070809000102030405060708090102', 'hex');
    expect(d.paymentHashHex).toBe(createHash('sha256').update(preimage).digest('hex'));
  });

  it('decodes the issuer-signed fixture', () => {
    const d = decodeBolt11(FIXTURE_INVOICE);
    expect(d.amountMsat).toBe(40_000n);
    expect(d.timestamp).toBe(1_800_000_000);
    expect(d.expirySecs).toBe(900);
    expect(d.descriptionHashHex).toBe(FIXTURE_REQUEST_HASH);
    expect(d.payeeHex).toBe(KEY_ONE);
    expect(d.paymentHashHex).toBe(FIXTURE_PAYMENT_HASH);
    expect(createHash('sha256').update(Buffer.from(FIXTURE_PREIMAGE, 'hex')).digest('hex')).toBe(FIXTURE_PAYMENT_HASH);
  });

  it('rejects a tampered invoice', () => {
    const tampered = SPEC_INVOICE.slice(0, 40) + (SPEC_INVOICE[40] === 'q' ? 'p' : 'q') + SPEC_INVOICE.slice(41);
    expect(() => decodeBolt11(tampered)).toThrow(/checksum|signature/);
    expect(() => decodeBolt11('lnbc1notaninvoice')).toThrow();
    expect(decodeBolt11(SPEC_INVOICE.toUpperCase()).payeeHex).toBe(KEY_ONE);
  });
});
