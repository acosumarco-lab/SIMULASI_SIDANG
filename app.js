/**
 * ===================================================================================
 * TUGAS AKHIR: SECURE MEDICAL IOT — WEB RECEIVER (JavaScript)
 * ===================================================================================
 * Deskripsi:
 *   Aplikasi web penerima yang menerima data detak jantung yang sudah di-watermark
 *   dari ESP32 via MQTT WebSocket, lalu melakukan verifikasi integritas menggunakan
 *   teknik DWT Haar + QIM + SHA-256.
 *
 * Alur Kerja:
 *   1. Terhubung ke MQTT broker via WebSocket (wss://)
 *   2. Menerima 2 tipe paket: "live" (BPM real-time) dan "secure" (blok watermark)
 *   3. Untuk paket "secure":
 *      a. Opsional: simulasi serangan (NOISE / ATTACK_BPM / ATTACK_KEY)
 *      b. Dekomposisi DWT Haar
 *      c. Regenerasi expected watermark dari SHA-256
 *      d. Ekstraksi watermark dari koefisien detail via QIM
 *      e. Bandingkan expected vs extracted → hitung BER
 *      f. Update UI: grafik, status, metrik, log
 *
 * Mode Pengujian:
 *   - NORMAL:      Data asli tanpa modifikasi
 *   - NOISE:       Tambah noise ±0.4 (simulasi gangguan transmisi)
 *   - ATTACK_BPM:  Tambah +30 ke semua nilai BPM (serangan manipulasi data)
 *   - ATTACK_KEY:  Penyerang mencoba re-watermark dengan password & sequence palsu
 *                  → simulasi penyerang yang tidak tahu SECRET_KEY dan urutan paket
 *
 * Dependensi (dimuat via CDN di index.html):
 *   - Chart.js   : Grafik real-time
 *   - MQTT.js    : Koneksi MQTT via WebSocket
 *   - js-sha256  : Hashing SHA-256
 * ===================================================================================
 */

// ===================================================================================
// BAGIAN 1: KONFIGURASI
// ===================================================================================
const CFG = {
    // --- Koneksi MQTT ---
    MQTT_URL: 'wss://broker.emqx.io:8084/mqtt',      // URL broker MQTT via WebSocket (port 8084 = WSS)
    MQTT_TOPIC: 'polban/iot/jantung/syauqi',           // Topic MQTT (HARUS SAMA dengan pengirim)

    // --- Keamanan Watermark ---
    SECRET_KEY: 'RahasiaPolban',     // Kunci rahasia untuk verifikasi (HARUS SAMA dengan pengirim)
    QIM_DELTA: 4.0,                  // Step size QIM (HARUS SAMA dengan pengirim)
    BER_THRESHOLD: 12.5,             // Batas maksimal BER (%)
    PSNR_THRESHOLD: 35.0,            // Batas minimal PSNR (dB) — di bawah ini dianggap manipulasi
    MAX_BPM_REF: 200.0,             // Nilai referensi untuk perhitungan PSNR

    // --- Parameter Serangan ATTACK_KEY ---
    FAKE_KEY: 'INIKUNCIPALSU',       // Kunci palsu — dipakai saat mode ATTACK_KEY

    // --- UI/Chart ---
    CHART_MAX: 60,                   // Maksimal data point di grafik BPM
    BER_CHART_MAX: 20,               // Maksimal bar di grafik BER history
    LOG_MAX_LINES: 10000,            // Maksimal baris log (Cukup untuk ~300 blok)
    ALERT_BPM_LOW: 40,              // Batas BPM rendah untuk alert
    ALERT_BPM_HIGH: 180,            // Batas BPM tinggi untuk alert
};

// ===================================================================================
// BAGIAN 2: STATE (Variabel Global)
// ===================================================================================
let attackMode = 'NORMAL';           // Mode simulasi serangan yang aktif
let bpmHistory = [];                 // Array riwayat BPM untuk grafik
let bufferTimeHistory = [];          // Array riwayat waktu buffer antar data (detik)
let lastLiveTimestamp = null;        // Timestamp terakhir data live diterima (ms)
let berHistory = [];                 // Array riwayat BER untuk grafik
let blockHistory = [];               // Array riwayat verifikasi blok (untuk tabel)
let dataHistory = [];                // Array riwayat data Raw vs Watermarked (untuk tabel)
let bpmChart = null;                 // Instance Chart.js untuk grafik BPM
let compareChart = null;             // Instance Chart.js untuk grafik perbandingan
let mqttClient = null;               // Instance MQTT client

// Statistik kumulatif
let stats = {
    packetCount: 0,                  // Total paket live yang diterima
    blockCount: 0,                   // Total blok secure yang diproses
    validBlocks: 0,                  // Jumlah blok yang valid (watermark cocok)
    invalidBlocks: 0,                // Jumlah blok yang invalid (watermark tidak cocok)
    allBPM: [],                      // Array seluruh nilai BPM untuk statistik
    lastBlockTime: null,             // Timestamp blok secure terakhir
};

// Statistik waktu komputasi ESP32
let compStats = {
    values: [],                      // Array waktu komputasi (ms)
    avg: 0,
    max: 0,
};


let packetHistory = [];              // Array untuk riwayat paket masuk (event-driven)

// ===================================================================================
// BAGIAN 3: DOM REFERENCES
// ===================================================================================
// Fungsi helper untuk mendapatkan elemen DOM berdasarkan ID
const $ = (id) => document.getElementById(id);

// Kumpulan referensi elemen DOM yang sering digunakan
const dom = {
    // Header
    mqttBadge: $('mqttBadge'),       // Badge status koneksi MQTT
    clock: $('clock'),               // Jam digital

    // Statistik
    bpmValue: $('bpmValue'),         // Nilai BPM live
    bpmZone: $('bpmZone'),           // Badge zona heart rate
    avgValue: $('avgValue'),         // Nilai BPM rata-rata
    minValue: $('minValue'),         // Nilai BPM minimum
    maxValue: $('maxValue'),         // Nilai BPM maksimum
    packetCount: $('packetCount'),   // Counter paket
    blockCount: $('blockCount'),     // Counter blok

    latencyValue: $('latencyValue'), // Nilai latency
    lastBlockTime: $('lastBlockTime'), // Waktu blok terakhir
    dpCount: $('dpCount'),           // Jumlah data point di grafik

    // Computation Time
    compValue: $('compValue'),       // Nilai waktu komputasi
    compAvg: $('compAvg'),           // Rata-rata waktu komputasi
    compMax: $('compMax'),           // Max waktu komputasi

    // Watermark Status
    wmIcon: $('wmIcon'),             // Ikon status watermark (✅ atau ⚠️)
    wmStatusText: $('wmStatusText'), // Text status watermark
    mBER: $('mBER'),                 // Metrik BER
    mPSNR: $('mPSNR'),             // Metrik PSNR
    mMSE: $('mMSE'),               // Metrik MSE
    mSEQ: $('mSEQ'),               // Metrik sequence number
    integrityPct: $('integrityPct'), // Persentase integritas
    integrityFill: $('integrityFill'), // Progress bar integritas
    validBlocks: $('validBlocks'),   // Label blok valid
    invalidBlocks: $('invalidBlocks'), // Label blok invalid
    modeBadge: $('modeBadge'),       // Badge mode simulasi
    compareMetrics: $('compareMetrics'), // Metrik perbandingan raw vs watermarked

    // History Tables
    blockHistBody: $('blockHistBody'),   // Tbody tabel history verifikasi
    blockHistCount: $('blockHistCount'), // Badge counter blok
    dataHistBody: $('dataHistBody'),     // Tbody tabel history data
    dataHistCount: $('dataHistCount'),   // Badge counter data
    btnDownloadCSV: $('btnDownloadCSV'), // Tombol export CSV

    btnDownloadLog: $('btnDownloadLog'), // Tombol export Log

    // Alert
    alertBar: $('alertBar'),         // Container alert
    alertMsg: $('alertMsg'),         // Pesan alert
    alertClose: $('alertClose'),     // Tombol tutup alert

    // Log
    logArea: $('logArea'),           // Area log output
    logWrap: $('logWrap'),           // Wrapper log (untuk scroll)
    btnClear: $('btnClear'),         // Tombol clear log
    autoScrollToggle: $('autoScrollToggle'), // Checkbox auto-scroll

    // Logo
    logoIcon: $('logoIcon'),         // Ikon logo (untuk animasi heartbeat)
};

// ===================================================================================
// BAGIAN 4: FUNGSI MATEMATIKA (Identik dengan sender.ino & receiver.py)
// ===================================================================================

/**
 * Haar Discrete Wavelet Transform (DWT).
 * Memecah sinyal input menjadi 2 komponen:
 * - cA (Approximation): rata-rata ternormalisasi (tren sinyal)
 * - cD (Detail): selisih ternormalisasi (detail/noise)
 *
 * Rumus:
 *   cA[i] = (data[2i] + data[2i+1]) × (1/√2)
 *   cD[i] = (data[2i] - data[2i+1]) × (1/√2)
 *
 * @param {number[]} data - Array 16 sampel BPM
 * @returns {{cA: Float64Array, cD: Float64Array}} - Koefisien approximation dan detail
 */
function haarDWT(data) {
    const half = data.length / 2;                // Setengah panjang input (= 8)
    const INV_SQRT2 = 0.70710678118;             // 1/√2 — perkalian lebih cepat dari pembagian
    const cA = new Float64Array(half);           // Array koefisien approximation
    const cD = new Float64Array(half);           // Array koefisien detail
    for (let i = 0; i < half; i++) {
        cA[i] = (data[2 * i] + data[2 * i + 1]) * INV_SQRT2;  // Rata-rata ternormalisasi
        cD[i] = (data[2 * i] - data[2 * i + 1]) * INV_SQRT2;  // Selisih ternormalisasi
    }
    return { cA, cD };
}

/**
 * Haar Inverse DWT (IDWT) — Rekonstruksi sinyal.
 * Menggabungkan kembali cA dan cD menjadi sinyal utuh.
 *
 * Rumus:
 *   output[2i]     = (cA[i] + cD[i]) × (1/√2)
 *   output[2i + 1] = (cA[i] - cD[i]) × (1/√2)
 *
 * @param {Float64Array} cA - Koefisien approximation
 * @param {Float64Array} cD - Koefisien detail (mungkin sudah dimodifikasi)
 * @returns {number[]} - Array sinyal hasil rekonstruksi
 */
function haarIDWT(cA, cD) {
    const INV_SQRT2 = 0.70710678118;
    const output = [];
    for (let i = 0; i < cA.length; i++) {
        output.push((cA[i] + cD[i]) * INV_SQRT2);    // Rekonstruksi sampel genap
        output.push((cA[i] - cD[i]) * INV_SQRT2);    // Rekonstruksi sampel ganjil
    }
    return output;
}

/**
 * Pembulatan robust ke kelipatan 5 terdekat.
 * HARUS IDENTIK dengan implementasi di sender.ino dan receiver.py.
 *
 * Rumus: floor((n / 5) + 0.5) × 5
 *
 * Contoh:
 *   92.63 → floor(92.63/5 + 0.5) = floor(18.526 + 0.5) = 19 → 95
 *   87.7  → floor(87.7/5 + 0.5)  = floor(17.54 + 0.5) = 18 → 90
 *
 * @param {number} n - Nilai yang akan dibulatkan
 * @returns {number} - Kelipatan 5 terdekat
 */
function robustRound(n) {
    return Math.floor((n / 5.0) + 0.5) * 5;
}

/**
 * Ekstraksi 1 bit watermark dari koefisien detail menggunakan QIM.
 *
 * Prinsip:
 * 1. Bagi koefisien dengan delta → dapat "step"
 * 2. Bulatkan ke bilangan bulat terdekat
 * 3. Ganjil → bit = 1, Genap → bit = 0
 *
 * @param {number} val - Nilai koefisien detail
 * @returns {string} - '0' atau '1'
 */
function extractQIMBit(val) {
    const rounded = Math.round(val / CFG.QIM_DELTA);  // Hitung dan bulatkan step
    return (rounded % 2 !== 0) ? '1' : '0';           // Ganjil=1, Genap=0
}

/**
 * Generate expected watermark bits dari SHA-256 hash.
 *
 * Alur:
 * 1. Robust round setiap cA → kelipatan 5 → gabung jadi string
 * 2. Gabung: "angka" + SECRET_KEY + seq
 * 3. SHA-256 hash
 * 4. Ambil numBits pertama dari hash (dalam biner)
 *
 * @param {Float64Array} cA - Koefisien approximation
 * @param {number} seq - Nomor sequence blok
 * @param {number} numBits - Jumlah bit yang dibutuhkan (= jumlah cD koefisien = 8)
 * @param {string} [key=CFG.SECRET_KEY] - Kunci rahasia (opsional, default: kunci asli)
 * @returns {{bits: string, raw: string, hex: string}} - Watermark bits, input string, hex hash
 */
function getExpectedBits(cA, seq, numBits, key) {
    // Gunakan kunci default jika tidak diberikan
    const secretKey = key || CFG.SECRET_KEY;

    // Langkah 1: Robust round setiap koefisien cA ke 5
    let s = '';
    for (let i = 0; i < cA.length; i++) s += robustRound(cA[i]).toString();

    // Langkah 2: Gabung dengan secret key dan sequence
    const raw = s + secretKey + seq.toString();

    // Langkah 3: SHA-256 hash
    const hex = sha256(raw);

    // Langkah 4: Konversi hex → biner, ambil numBits pertama
    let bits = '';
    const bytesNeeded = Math.ceil(numBits / 8);   // Berapa byte yang perlu dikonversi
    for (let i = 0; i < bytesNeeded; i++) {
        // Ambil 2 karakter hex (= 1 byte), konversi ke 8 bit biner
        bits += parseInt(hex.substring(i * 2, i * 2 + 2), 16).toString(2).padStart(8, '0');
    }
    bits = bits.substring(0, numBits);            // Potong ke jumlah bit yang dibutuhkan

    return { bits, raw, hex };
}

/**
 * Embed watermark palsu ke koefisien detail menggunakan QIM.
 * Digunakan dalam mode ATTACK_KEY.
 *
 * Prinsip sama dengan pengirim:
 * - step = floor(cD[i] / delta)
 * - Jika paritas step ≠ bit watermark → naikkan step
 * - cD[i] = step × delta
 *
 * @param {Float64Array} cD - Array koefisien detail
 * @param {string} watermarkBits - String bit watermark palsu (misal "10110010")
 * @returns {Float64Array} - Array cD yang sudah di-embed watermark palsu
 */
function embedQIMAttack(cD, watermarkBits) {
    const result = new Float64Array(cD.length);   // Buat copy baru
    for (let i = 0; i < cD.length; i++) {
        const val = cD[i];                         // Nilai koefisien asli
        const bit = parseInt(watermarkBits[i % watermarkBits.length]);  // Bit watermark palsu
        let step = Math.floor(val / CFG.QIM_DELTA);  // Hitung step
        if (Math.abs(step % 2) !== bit) {          // Jika paritas tidak cocok
            step++;                                 // Naikkan step
        }
        result[i] = step * CFG.QIM_DELTA;          // Koefisien baru
    }
    return result;
}

// ===================================================================================
// BAGIAN 5: VERIFIKASI WATERMARK
// ===================================================================================

/**
 * Fungsi utama verifikasi watermark.
 * Membandingkan watermark yang tertanam dalam data dengan yang seharusnya.
 *
 * Langkah-langkah:
 * [0] Tampilkan data mentah yang diterima
 * [1] Dekomposisi DWT → dapat cA dan cD
 * [2] Generate expected watermark dari SHA-256
 * [3] Ekstraksi watermark dari cD via QIM (detail per koefisien)
 * [4] Bandingkan expected vs extracted
 * [5] Kesimpulan: BER, MSE, PSNR, status
 *
 * @param {number[]} wmData - Data setelah watermarking (sebelum attack)
 * @param {number[]} processed - Data setelah attack simulation
 * @param {number} seq - Nomor urut blok
 * @param {string} mode - Mode pengujian ('NORMAL', 'NOISE', 'ATTACK_BPM', 'ATTACK_KEY')
 * @returns {{status: string, ber: number, mse: number, psnr: number, log: string}}
 */
function verifyWatermark(received, wmData, processed, seq, mode) {
    const log = [];  // Array untuk menyimpan baris-baris log

    // === HEADER ===
    log.push('='.repeat(50));
    log.push(`PROSES VERIFIKASI BLOK SEQ: ${seq}`);
    log.push('='.repeat(50));

    // === [0] DATA MASUK — tampilkan seluruh nilai ===
    log.push(`[0] Data Diterima (Raw ${processed.length}): [${processed.map(x => x.toFixed(2)).join(', ')}]`);

    // === HITUNG MSE & PSNR ===
    // Baseline MSE = Raw vs Watermarked
    // Final MSE = Raw vs Processed
    // Pure Attack MSE = Watermarked vs Processed (Bukti mutlak untuk dosen penguji)
    let mseBaselineSum = 0;
    let mseFinalSum = 0;
    let msePureAttackSum = 0;

    for (let i = 0; i < received.length; i++) {
        mseBaselineSum += (received[i] - wmData[i]) ** 2;
        mseFinalSum += (received[i] - processed[i]) ** 2;
        msePureAttackSum += (wmData[i] - processed[i]) ** 2;
    }

    const mseBaseline = mseBaselineSum / received.length;
    const mseFinal = mseFinalSum / received.length;
    const msePureAttack = msePureAttackSum / received.length; // Pasti 0.64 untuk kompresi Symmetrical
    const mseDiff = mseFinal - mseBaseline; // Berapa lonjakan MSE akibat serangan/kompresi?
    const psnr = mseFinal === 0 ? 100.0 : 20 * Math.log10(CFG.MAX_BPM_REF / Math.sqrt(mseFinal));

    // Hitung persentase kerusakan MSE relatif terhadap MAX_BPM^2
    const maxBpmSq = CFG.MAX_BPM_REF * CFG.MAX_BPM_REF; // 200^2 = 40000
    const mseBaselinePct = (mseBaseline / maxBpmSq) * 100;
    const mseFinalPct = (mseFinal / maxBpmSq) * 100;

    // Tampilkan info serangan jika bukan NORMAL
    if (mode !== 'NORMAL') {
        log.push(`[SIMULASI: ${mode}]`);
        log.push(`  > MSE Akhir    : ${mseFinal.toFixed(4)} (${mseFinalPct.toFixed(4)}% kerusakan) | PSNR: ${psnr.toFixed(2)} dB`);
        log.push(`  > MSE Baseline : ${mseBaseline.toFixed(4)} (${mseBaselinePct.toFixed(4)}% kerusakan watermark)`);
        log.push(`  > Lonjakan MSE : ${mseDiff > 0 ? '+' : ''}${mseDiff.toFixed(4)}`);
        log.push(`  > MSE Serangan Murni: ${msePureAttack.toFixed(4)} (Bukti Matematis Mutlak)`);
    } else {
        log.push(`  > MSE Bawaan (Watermark): ${mseBaseline.toFixed(4)} (${mseBaselinePct.toFixed(4)}% kerusakan sinyal)`);
    }

    // === [1] DWT — dekomposisi sinyal ===
    const { cA, cD } = haarDWT(processed);
    log.push(`[1] LL (Sinyal Utama): [${Array.from(cA).map(x => x.toFixed(2)).join(', ')}]`);
    log.push(`[1] LH (Detail/Koefisien): [${Array.from(cD).map(x => x.toFixed(2)).join(', ')}]`);

    // === [2] HASH SHA-256 ===
    // Pilih kunci: jika ATTACK_KEY → pakai FAKE_KEY, selainnya → SECRET_KEY
    const kunci = (mode === 'ATTACK_KEY') ? CFG.FAKE_KEY : CFG.SECRET_KEY;
    log.push(`[2] Proses Hash SHA-256 (Kunci: ${kunci})...`);
    const numBits = cD.length;
    const { bits: expected, raw, hex } = getExpectedBits(cA, seq, numBits, kunci);
    log.push(`  > [HASH] Input String (Robust): ${raw}`);
    log.push(`  > [HASH] Hex: ${hex}`);
    log.push(`  > [HASH] Expected Watermark Bits: ${expected}`);

    // === [3] EKSTRAKSI QIM — detail per koefisien ===
    log.push('[3] Ekstraksi QIM dari LH...');
    let extracted = '';
    for (let i = 0; i < cD.length; i++) {
        const val = cD[i];                         // Nilai koefisien detail
        const rounded = Math.round(val / CFG.QIM_DELTA);  // Hitung step
        const bit = (rounded % 2 !== 0) ? '1' : '0';     // Ganjil=1, Genap=0
        extracted += bit;
        // Log detail setiap koefisien
        log.push(`  > cD[${i}] = ${val.toFixed(4)} → step=${rounded} → bit=${bit}`);
    }
    log.push(`  > [QIM] Extracted Bits: ${extracted}`);

    // === [4] VERIFIKASI — bandingkan expected vs extracted ===
    log.push('[4] Verifikasi Integritas');
    log.push(`  > Harapan: ${expected}`);
    log.push(`    Fakta:   ${extracted}`);

    // Hitung jumlah bit yang berbeda (error)
    let errors = 0;
    for (let i = 0; i < numBits; i++) if (extracted[i] !== expected[i]) errors++;
    // BER (Bit Error Rate): persentase bit yang salah
    const ber = (errors / numBits) * 100;

    // === [5] KESIMPULAN ===
    // Syarat valid: HANYA berdasarkan BER (Bit Error Rate)
    // Toleransi: BER <= 12.5% (maksimal 1 bit error dari 8 bit payload)
    // MSE dan PSNR tetap dihitung sebagai metrik observasi/analisis
    const isBerValid = ber <= CFG.BER_THRESHOLD;
    const isAuthentic = isBerValid;
    const status = isAuthentic ? 'VALID' : 'INVALID';
    log.push('[5] KESIMPULAN');
    log.push(`  > Error Bits: ${errors}/${numBits}`);
    log.push(`  > BER: ${ber.toFixed(2)}% (Threshold: ${CFG.BER_THRESHOLD}%)`);
    log.push(`  > PSNR: ${psnr.toFixed(2)} dB | MSE: ${mseFinal.toFixed(4)} (observasi)`);
    log.push(`  > Tambahan MSE akibat serangan: +${mseDiff.toFixed(4)}`);

    if (isAuthentic) {
        log.push('  > STATUS: [VALID] DATA OTENTIK');
    } else {
        log.push(`  > STATUS: [INVALID] DATA DIMANIPULASI (BER ${ber.toFixed(2)}% > ${CFG.BER_THRESHOLD}%)`);
    }
    log.push('='.repeat(50));

    return { status, ber, mse: mseFinal, psnr, wmExtracted: extracted, wmExpected: expected, invalidReason: isAuthentic ? '' : `BER ${ber.toFixed(2)}% > ${CFG.BER_THRESHOLD}%`, log: log.join('\n') };
}

// ===================================================================================
// BAGIAN 6: HEART RATE ZONES
// ===================================================================================

/**
 * Tentukan zona heart rate berdasarkan nilai BPM.
 *
 * Zona:
 * - Rest:     BPM < 60
 * - Moderate: 60 ≤ BPM < 100
 * - Cardio:   100 ≤ BPM < 140
 * - Peak:     BPM ≥ 140
 *
 * @param {number} bpm - Nilai BPM
 * @returns {{label: string, cls: string}} - Label dan CSS class untuk zona
 */
function getHRZone(bpm) {
    if (bpm < 60) return { label: 'Rest', cls: 'rest' };
    if (bpm < 100) return { label: 'Moderate', cls: 'moderate' };
    if (bpm < 140) return { label: 'Cardio', cls: 'cardio' };
    return { label: 'Peak', cls: 'peak' };
}

// ===================================================================================
// BAGIAN 7: CHARTS (Chart.js)
// ===================================================================================

/**
 * Inisialisasi grafik BPM dan BER menggunakan Chart.js.
 */
function initCharts() {
    // Warna untuk light theme
    const gridColor = 'rgba(0, 0, 0, 0.06)';
    const tickColor = '#4a5568';
    const tickFont = { size: 14, family: "'Plus Jakarta Sans', sans-serif", weight: '600' };
    const tooltipStyle = {
        backgroundColor: '#ffffff',
        titleColor: '#1a202c',
        bodyColor: '#4a5568',
        borderColor: '#e2e8f0',
        borderWidth: 1,
        cornerRadius: 10,
        padding: 10,
        displayColors: false
    };

    // --- Grafik BPM (Line Chart) ---
    const ctx1 = $('bpmChart').getContext('2d');
    const grad = ctx1.createLinearGradient(0, 0, 0, 280);
    grad.addColorStop(0, 'rgba(220, 38, 38, 0.15)');
    grad.addColorStop(1, 'rgba(220, 38, 38, 0)');

    bpmChart = new Chart(ctx1, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                data: [],
                borderColor: '#dc2626',
                backgroundColor: grad,
                borderWidth: 2.5,
                fill: true,
                tension: 0.4,
                pointRadius: 4,
                pointBackgroundColor: '#dc2626'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 0 },
            scales: {
                x: {
                    display: true,
                    title: { display: true, text: 'Data ke-n', color: tickColor, font: tickFont },
                    grid: { display: true, color: gridColor, drawBorder: false },
                    ticks: { display: true, color: tickColor, font: { size: 13 } }
                },
                y: {
                    title: { display: true, text: 'Waktu Buffer (detik)', color: tickColor, font: tickFont },
                    grid: { color: gridColor, drawBorder: false },
                    ticks: { color: tickColor, font: tickFont },
                    beginAtZero: true
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: tooltipStyle
            },
            interaction: { intersect: false, mode: 'index' }
        }
    });

    // --- Grafik Perbandingan Raw vs Watermarked (Line Chart) ---
    const ctx3 = $('compareChart').getContext('2d');
    compareChart = new Chart(ctx3, {
        type: 'line',
        data: {
            labels: Array.from({ length: 16 }, (_, i) => `S${i + 1}`),
            datasets: [
                {
                    label: 'Raw (Asli)',
                    data: [],
                    borderColor: '#4f46e5',
                    backgroundColor: 'rgba(79, 70, 229, 0.08)',
                    borderWidth: 2.5,
                    fill: false,
                    tension: 0.3,
                    pointRadius: 4,
                    pointBackgroundColor: '#4f46e5'
                },
                {
                    label: 'Watermarked',
                    data: [],
                    borderColor: '#dc2626',
                    backgroundColor: 'rgba(220, 38, 38, 0.08)',
                    borderWidth: 2.5,
                    borderDash: [6, 3],
                    fill: false,
                    tension: 0.3,
                    pointRadius: 4,
                    pointBackgroundColor: '#dc2626'
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 300 },
            scales: {
                x: {
                    title: { display: true, text: 'Sampel ke-n (1–16)', color: tickColor, font: tickFont },
                    grid: { display: false },
                    ticks: { color: tickColor, font: { size: 13 } }
                },
                y: {
                    title: { display: true, text: 'Nilai BPM', color: tickColor, font: tickFont },
                    grid: { color: gridColor, drawBorder: false },
                    ticks: { color: tickColor, font: tickFont }
                }
            },
            plugins: {
                legend: {
                    display: true,
                    labels: { color: tickColor, font: { size: 14, family: "'Plus Jakarta Sans', sans-serif", weight: '600' }, usePointStyle: true, pointStyle: 'circle' }
                },
                tooltip: tooltipStyle
            }
        }
    });
}

/**
 * Tambahkan data point baru ke grafik Buffer Time.
 * Menampilkan maksimal CHART_MAX (60) data point terakhir.
 * Menghitung waktu (detik) antara data saat ini dan data sebelumnya.
 *
 * @param {number} bufferTimeSec - Waktu buffer dalam detik
 */
function pushBufferTimeChart(bufferTimeSec) {
    bufferTimeHistory.push(bufferTimeSec);             // Tambah data baru
    if (bufferTimeHistory.length > CFG.CHART_MAX) bufferTimeHistory.shift();  // Hapus data tertua

    bpmChart.data.labels = bufferTimeHistory.map((_, i) => i);          // Update label X (data ke-n)
    bpmChart.data.datasets[0].data = [...bufferTimeHistory];            // Update data Y (waktu buffer)
    bpmChart.update('none');                           // Update tanpa animasi
    dom.dpCount.textContent = `${bufferTimeHistory.length} pts`;  // Update counter
}

// ===================================================================================
// BAGIAN 8: UI UPDATE
// ===================================================================================

/**
 * Update tampilan BPM live — dipanggil setiap menerima paket "live".
 *
 * @param {number} val - Nilai BPM
 */
function updateLiveBPM(val) {
    // Update angka BPM
    dom.bpmValue.textContent = val;

    // Hitung waktu buffer (detik) sejak data terakhir
    const now = Date.now();
    if (lastLiveTimestamp !== null) {
        const deltaMs = now - lastLiveTimestamp;
        const deltaSec = deltaMs / 1000.0;
        pushBufferTimeChart(parseFloat(deltaSec.toFixed(2)));  // Update grafik buffer time
    }
    lastLiveTimestamp = now;

    // Update zona heart rate
    const zone = getHRZone(val);
    const badge = dom.bpmZone.querySelector('.zone-badge');
    badge.textContent = zone.label;
    badge.className = `zone-badge ${zone.cls}`;       // Set warna sesuai zona

    // Update statistik
    stats.packetCount++;
    stats.allBPM.push(val);
    dom.packetCount.textContent = stats.packetCount;

    // Hitung min / max / avg
    const min = Math.min(...stats.allBPM);
    const max = Math.max(...stats.allBPM);
    const avg = (stats.allBPM.reduce((s, v) => s + v, 0) / stats.allBPM.length).toFixed(0);
    dom.avgValue.textContent = avg;
    dom.minValue.textContent = `Min: ${min}`;
    dom.maxValue.textContent = `Max: ${max}`;

    // Batasi array BPM (mencegah memory leak pada operasi lama)
    if (stats.allBPM.length > 1000) stats.allBPM = stats.allBPM.slice(-500);

    // Trigger animasi heartbeat pada logo
    dom.logoIcon.style.animation = 'none';
    void dom.logoIcon.offsetWidth;                    // Force reflow
    dom.logoIcon.style.animation = 'pulse-logo 2s ease-in-out infinite';

    // Alert untuk BPM abnormal
    if (val < CFG.ALERT_BPM_LOW) {
        showAlert(`BPM rendah terdeteksi: ${val} BPM (< ${CFG.ALERT_BPM_LOW})`, 'warning');
    } else if (val > CFG.ALERT_BPM_HIGH) {
        showAlert(`BPM tinggi terdeteksi: ${val} BPM (> ${CFG.ALERT_BPM_HIGH})`, 'danger');
    }
}

/**
 * Update tampilan hasil verifikasi watermark — dipanggil setiap menerima paket "secure".
 *
 * @param {Object} result - Hasil dari verifyWatermark()
 * @param {number} seq - Nomor sequence blok
 */
function updateSecure(result, seq) {
    // Update metrik
    dom.mBER.textContent = `${result.ber.toFixed(2)}%`;
    dom.mPSNR.textContent = `${result.psnr.toFixed(2)} dB`;
    dom.mMSE.textContent = result.mse.toFixed(4);
    dom.mSEQ.textContent = `#${seq}`;

    // Update ikon dan teks status
    if (result.status === 'VALID') {
        dom.wmIcon.innerHTML = '<i data-lucide="shield-check" style="width:48px;height:48px;stroke-width:1.5;"></i>';
        dom.wmIcon.className = 'wm-icon valid';
        dom.wmStatusText.textContent = 'DATA OTENTIK';
        dom.wmStatusText.className = 'wm-status-text valid';
        stats.validBlocks++;
    } else {
        dom.wmIcon.innerHTML = '<div class="beacon-dot"></div>';
        dom.wmIcon.className = 'wm-icon beacon-danger';
        dom.wmStatusText.textContent = 'DATA DIMANIPULASI';
        dom.wmStatusText.className = 'wm-status-text invalid';
        stats.invalidBlocks++;
    }

    if (window.lucide) lucide.createIcons({ root: dom.wmIcon });

    // Update counter blok
    stats.blockCount++;
    dom.blockCount.textContent = `Blocks: ${stats.blockCount}`;

    // Hitung latency (waktu sejak blok terakhir)
    const now = new Date();
    if (stats.lastBlockTime) {
        const diff = ((now - stats.lastBlockTime) / 1000).toFixed(1);
        dom.latencyValue.textContent = `${diff}s`;
    }
    stats.lastBlockTime = now;
    dom.lastBlockTime.textContent = `Blok terakhir: ${now.toLocaleTimeString('id-ID')}`;

    // Update integrity score (persentase blok valid)
    const total = stats.validBlocks + stats.invalidBlocks;
    const pct = total > 0 ? ((stats.validBlocks / total) * 100).toFixed(1) : 0;
    dom.integrityPct.textContent = `${pct}%`;
    dom.integrityFill.style.width = `${pct}%`;
    dom.validBlocks.innerHTML = `<i data-lucide="check-circle-2" class="inline-icon"></i> ${stats.validBlocks} valid`;
    dom.invalidBlocks.innerHTML = `<i data-lucide="x-circle" class="inline-icon"></i> ${stats.invalidBlocks} invalid`;
    if (window.lucide) {
        lucide.createIcons({ root: dom.validBlocks });
        lucide.createIcons({ root: dom.invalidBlocks });
    }

    // Warna progress bar berdasarkan persentase
    if (pct >= 80) {
        dom.integrityFill.style.background = 'linear-gradient(90deg, #16a34a, #0891b2)';  // Hijau
        dom.integrityPct.style.color = '#16a34a';
    } else if (pct >= 50) {
        dom.integrityFill.style.background = 'linear-gradient(90deg, #d97706, #ea580c)';  // Kuning
        dom.integrityPct.style.color = '#d97706';
    } else {
        dom.integrityFill.style.background = 'linear-gradient(90deg, #dc2626, #b91c1c)';  // Merah
        dom.integrityPct.style.color = '#dc2626';
    }


    // Tambahkan log detail
    appendLog(result.log);
}

/**
 * Tambah baris ke tabel History Verifikasi Blok.
 * Menampilkan: Blok#, Waktu, Status (VALID/INVALID), Mode, BER, PSNR, MSE.
 *
 * @param {number} seq - Nomor sequence blok
 * @param {Object} result - Hasil verifikasi { status, ber, psnr, mse }
 * @param {string} mode - Mode serangan aktif
 */
function pushBlockHistory(seq, result, mode) {
    const MAX_ROWS = 300;
    const now = new Date().toLocaleTimeString('id-ID');
    const isValid = result.status === 'VALID';

    // Hapus placeholder "Belum ada data" jika ada
    const empty = dom.blockHistBody.querySelector('.empty-row');
    if (empty) empty.remove();

    // Buat baris baru (10 kolom)
    const tr = document.createElement('tr');
    const invalidReason = result.invalidReason || '';
    const keterangan = isValid ? 'Data Otentik' : invalidReason;
    tr.innerHTML = `
        <td><strong>#${seq}</strong></td>
        <td>${now}</td>
        <td><span class="${isValid ? 'badge-valid' : 'badge-invalid'}">${isValid ? '<i data-lucide="check" class="inline-icon" style="width:14px;height:14px;"></i> VALID' : '<i data-lucide="x" class="inline-icon" style="width:14px;height:14px;"></i> INVALID'}</span></td>
        <td>${mode}</td>
        <td class="td-num" style="font-family:monospace;font-size:12px;">${result.wmExpected || '-'}</td>
        <td class="td-num" style="font-family:monospace;font-size:12px;">${result.wmExtracted || '-'}</td>
        <td class="td-num">${result.ber.toFixed(2)}</td>
        <td class="td-num">${result.psnr.toFixed(2)}</td>
        <td class="td-num">${result.mse.toFixed(4)}</td>
        <td>${keterangan}</td>
    `;
    dom.blockHistBody.appendChild(tr);
    if (window.lucide) lucide.createIcons({ root: tr });

    // Limit rows
    blockHistory.push({ seq, status: result.status, mode, ber: result.ber, psnr: result.psnr, mse: result.mse, wmExtracted: result.wmExtracted || '', wmExpected: result.wmExpected || '', invalidReason: result.invalidReason || '', timestamp: new Date().toLocaleTimeString('id-ID') });
    if (blockHistory.length > MAX_ROWS) {
        blockHistory.shift();
        dom.blockHistBody.removeChild(dom.blockHistBody.firstElementChild);
    }

    // Update counter & scroll
    dom.blockHistCount.textContent = `${blockHistory.length} blok`;
    const wrap = dom.blockHistBody.closest('.table-wrap');
    if (wrap) wrap.scrollTop = wrap.scrollHeight;
}

/**
 * Tambah baris ke tabel History Data Raw vs Watermarked.
 * Menampilkan: Blok#, Sample#, Raw, Watermarked, Selisih.
 * Satu blok = 16 baris (satu per sampel).
 *
 * @param {number} seq - Nomor sequence blok
 * @param {number[]} raw - Data BPM asli
 * @param {number[]} watermarked - Data setelah watermarking
 * @param {string} mode - Mode serangan aktif
 * @param {number[]} dtArray - (Opsional) Array perbedaan waktu tiap sampel vs waktu tiba (dalam ms)
 */
function pushDataHistory(seq, raw, watermarked, mode, dtArray) {
    const MAX_BLOCKS = 300;
    if (!raw || !watermarked || raw.length === 0) return;

    // Hapus placeholder "Belum ada data" jika ada
    const empty = dom.dataHistBody.querySelector('.empty-row');
    if (empty) empty.remove();

    const now = new Date();

    // Tambahkan satu baris per sampel
    const len = Math.min(raw.length, watermarked.length);
    for (let i = 0; i < len; i++) {
        // Jika ada dtArray dari ESP32, gunakan itu. Jika tidak ada, fallback ke simulasi 1 detik = 1000ms.
        const dtOffset = (dtArray && dtArray.length === len) ? dtArray[i] : ((len - 1 - i) * 1000);
        const sampleTime = new Date(now.getTime() - dtOffset);
        const currentTime = sampleTime.toLocaleTimeString('id-ID', { hour12: false }) + '.' + String(sampleTime.getMilliseconds()).padStart(3, '0');

        const wmRounded = Math.round(watermarked[i]);  // Bulatkan ke integer
        const diff = Math.abs(wmRounded - raw[i]);
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${i === 0 ? '<strong>#' + seq + '</strong>' : ''}</td>
            <td>S${i + 1}</td>
            <td>${currentTime}</td>
            <td class="td-num">${raw[i]}</td>
            <td class="td-num">${wmRounded}</td>
            <td class="td-num">${diff}</td>
            <td>${i === 0 ? mode : ''}</td>
        `;
        dom.dataHistBody.appendChild(tr);
    }

    // Limit blocks tracked
    dataHistory.push({ seq, len });
    if (dataHistory.length > MAX_BLOCKS) {
        dataHistory.shift();
        // Remove oldest block's rows (= oldest len rows)
        const removeCount = dataHistory[0] ? len : len;
        for (let i = 0; i < len && dom.dataHistBody.firstElementChild; i++) {
            dom.dataHistBody.removeChild(dom.dataHistBody.firstElementChild);
        }
    }

    // Update counter & scroll
    dom.dataHistCount.textContent = `${dataHistory.length} blok`;
    const wrap = dom.dataHistBody.closest('.table-wrap');
    if (wrap) wrap.scrollTop = wrap.scrollHeight;
}

/**
 * Tampilkan alert bar dengan pesan dan tipe.
 * Auto-hide setelah 8 detik.
 *
 * @param {string} msg - Pesan alert
 * @param {string} type - Tipe: 'warning' atau 'danger'
 */
function showAlert(msg, type) {
    dom.alertBar.style.display = 'flex';
    dom.alertBar.className = `alert-bar ${type === 'warning' ? 'warning' : ''}`;
    dom.alertMsg.textContent = msg;

    // Auto-hide setelah 8 detik
    clearTimeout(window._alertTimer);
    window._alertTimer = setTimeout(() => { dom.alertBar.style.display = 'none'; }, 8000);
}

/**
 * Tambahkan teks ke area log. Batasi jumlah baris untuk mencegah memory leak.
 *
 * @param {string} text - Teks log yang akan ditambahkan
 */
function appendLog(text) {
    const el = dom.logArea;
    const lines = el.textContent.split('\n');
    // Trim log jika melebihi batas
    if (lines.length > CFG.LOG_MAX_LINES) {
        el.textContent = lines.slice(-CFG.LOG_MAX_LINES).join('\n');
    }
    el.textContent += '\n' + text + '\n';

    // Auto-scroll hanya jika switch auto-scroll dicentang
    if (dom.autoScrollToggle && dom.autoScrollToggle.checked) {
        dom.logWrap.scrollTop = dom.logWrap.scrollHeight;
    }
}

/**
 * Update badge status koneksi MQTT.
 *
 * @param {string} status - 'online', 'offline', atau '' (connecting)
 */
function setMQTT(status) {
    const badge = dom.mqttBadge;
    const txt = badge.querySelector('.mqtt-text');
    badge.className = 'mqtt-badge ' + (status === 'online' ? 'online' : status === 'offline' ? 'offline' : '');
    txt.textContent = status === 'online' ? 'Connected' : status === 'offline' ? 'Disconnected' : 'Connecting...';
}

// ===================================================================================
// BAGIAN 9: SIMULASI SERANGAN
// ===================================================================================

/**
 * Generate angka acak Gaussian (distribusi normal) menggunakan Box-Muller transform.
 * Standar IEEE untuk simulasi noise kanal nirkabel.
 *
 * @param {number} mean - Rata-rata distribusi (biasanya 0)
 * @param {number} sigma - Standar deviasi (menentukan kekuatan noise)
 * @returns {number} - Angka acak berdistribusi Gaussian
 */
function gaussianRandom(mean, sigma) {
    const u1 = Math.random();
    const u2 = Math.random();
    const z = Math.sqrt(-2.0 * Math.log(u1)) * Math.cos(2.0 * Math.PI * u2);
    return mean + z * sigma;
}

// ===================================================================================
// BAGIAN 9B: FUNGSI KOMPRESI LOSSLESS — Delta + Zigzag + Varint
// (Pipeline dari TA kolaborasi: kompresi data IoT)
// ===================================================================================

/**
 * Delta Encoding Orde 1: menyimpan selisih antar sampel berurutan.
 * output[0] = input[0], output[i] = input[i] - input[i-1]
 * @param {number[]} input
 * @returns {number[]}
 */
function deltaEncode_O1(input) {
    if (input.length === 0) return [];
    const output = [input[0]];
    for (let i = 1; i < input.length; i++) {
        output[i] = input[i] - input[i - 1];
    }
    return output;
}

/**
 * Delta Decoding Orde 1: inverse dari deltaEncode_O1.
 * @param {number[]} encoded
 * @returns {number[]}
 */
function deltaDecode_O1(encoded) {
    if (encoded.length === 0) return [];
    const output = [encoded[0]];
    for (let i = 1; i < encoded.length; i++) {
        output[i] = output[i - 1] + encoded[i];
    }
    return output;
}

/**
 * Delta Encoding Orde 2: menyimpan turunan kedua (selisih dari selisih).
 * output[0] = input[0], output[1] = input[1] - input[0],
 * output[i] = input[i] - 2*input[i-1] + input[i-2]
 * @param {number[]} input
 * @returns {number[]}
 */
function deltaEncode_O2(input) {
    if (input.length === 0) return [];
    const output = [input[0]];
    if (input.length > 1) output[1] = input[1] - input[0];
    for (let i = 2; i < input.length; i++) {
        output[i] = input[i] - 2 * input[i - 1] + input[i - 2];
    }
    return output;
}

/**
 * Delta Decoding Orde 2: inverse dari deltaEncode_O2.
 * @param {number[]} encoded
 * @returns {number[]}
 */
function deltaDecode_O2(encoded) {
    if (encoded.length === 0) return [];
    const output = [encoded[0]];
    if (encoded.length > 1) output[1] = encoded[1] + output[0];
    for (let i = 2; i < encoded.length; i++) {
        output[i] = encoded[i] + 2 * output[i - 1] - output[i - 2];
    }
    return output;
}

/**
 * Zigzag Encoding: memetakan signed integer ke unsigned integer.
 * Angka kecil (positif/negatif) tetap menjadi angka kecil unsigned.
 * Rumus: (value << 1) ^ (value >> 31)
 * @param {number} value - Signed integer
 * @returns {number} - Unsigned integer
 */
function zigzagEncode(value) {
    return (value << 1) ^ (value >> 31);
}

/**
 * Zigzag Decoding: inverse dari zigzagEncode.
 * @param {number} value - Unsigned integer
 * @returns {number} - Signed integer
 */
function zigzagDecode(value) {
    return (value >>> 1) ^ -(value & 1);
}

/**
 * Varint Encoding: variable-length encoding untuk unsigned integer.
 * Angka kecil menggunakan sedikit byte (1 byte untuk 0-127).
 * @param {number} value - Unsigned integer
 * @returns {number[]} - Array of bytes
 */
function varintEncode(value) {
    const bytes = [];
    value = value >>> 0; // ensure unsigned
    while (value >= 0x80) {
        bytes.push((value & 0x7F) | 0x80);
        value >>>= 7;
    }
    bytes.push(value & 0xFF);
    return bytes;
}

/**
 * Varint Decoding: decode satu varint dari array byte mulai index tertentu.
 * @param {number[]} bytes - Array byte stream
 * @param {number} startIndex - Posisi mulai membaca
 * @returns {{value: number, bytesRead: number}}
 */
function varintDecodeSingle(bytes, startIndex) {
    let value = 0, shift = 0, i = startIndex;
    while (i < bytes.length && (bytes[i] & 0x80)) {
        value |= (bytes[i] & 0x7F) << shift;
        shift += 7;
        i++;
    }
    if (i < bytes.length) {
        value |= (bytes[i] & 0x7F) << shift;
    }
    return { value: value >>> 0, bytesRead: i - startIndex + 1 };
}

/**
 * Decode seluruh array varint menjadi array unsigned integer.
 * @param {number[]} bytes - Varint-encoded byte stream
 * @returns {number[]} - Array of decoded unsigned integers
 */
function varintDecodeArray(bytes) {
    const result = [];
    let idx = 0;
    while (idx < bytes.length) {
        const { value, bytesRead } = varintDecodeSingle(bytes, idx);
        result.push(value);
        idx += bytesRead;
    }
    return result;
}

/**
 * Full lossless compression pipeline: Delta → Zigzag → Varint.
 * @param {number[]} intData - Array of integers
 * @param {number} orde - 1 atau 2
 * @returns {{compressed: number[], originalSize: number, compressedSize: number}}
 */
function deltaZigzagVarintCompress(intData, orde) {
    const delta = (orde === 2) ? deltaEncode_O2(intData) : deltaEncode_O1(intData);
    const zigzag = delta.map(zigzagEncode);
    const varint = zigzag.flatMap(varintEncode);
    return {
        compressed: varint,
        originalSize: intData.length * 4, // 4 bytes per int32
        compressedSize: varint.length,
    };
}

/**
 * Full lossless decompression pipeline: Varint → Zigzag → Delta.
 * @param {number[]} compressed - Varint byte stream
 * @param {number} orde - 1 atau 2
 * @returns {number[]} - Reconstructed integer array
 */
function deltaZigzagVarintDecompress(compressed, orde) {
    const zigzagValues = varintDecodeArray(compressed);
    const deltaValues = zigzagValues.map(zigzagDecode);
    return (orde === 2) ? deltaDecode_O2(deltaValues) : deltaDecode_O1(deltaValues);
}

// ===================================================================================
// BAGIAN 9C: SIMULASI SERANGAN & KOMPRESI
// ===================================================================================

/**
 * Terapkan simulasi serangan pada data yang diterima.
 *
 * Mode yang didukung:
 * - NORMAL:          Data dikembalikan tanpa perubahan
 * - SYM_COMP_05:     Kompresi Simetris ringan (+0.5, -0.5)
 * - SYM_COMP_10:     Kompresi Simetris sedang (+1.0, -1.0)
 * - SYM_COMP_20:     Kompresi Simetris berat (+2.0, -2.0)
 * - AWGN_VAR_001:    Gaussian noise variance=0.01 (σ≈0.1) — noise ringan
 * - AWGN_VAR_1:      Gaussian noise variance=1.0  (σ=1.0) — noise sedang
 * - AWGN_VAR_10:     Gaussian noise variance=10.0 (σ≈3.16) — noise berat
 * - COMPRESS_Q50:    Lossy compression Q=50 (ringan)
 * - COMPRESS_Q30:    Lossy compression Q=30 (sedang)
 * - COMPRESS_Q10:    Lossy compression Q=10 (berat)
 * - DELTA_LOSSLESS_O1: Kompresi lossless Delta Orde 1 + Zigzag + Varint (compress → decompress)
 * - DELTA_LOSSLESS_O2: Kompresi lossless Delta Orde 2 + Zigzag + Varint (compress → decompress)
 * - DELTA_CORRUPT:     Kompresi lossless + corrupt 2 byte → decompress (simulasi kerusakan kanal)
 * - ATTACK_BPM:      Tambah 30 ke semua nilai konstan (manipulasi data langsung)
 * - ATTACK_BPM_LINEAR: Tambah nilai bertahap (+5, +10, dst)
 * - ATTACK_KEY:      Data tidak diubah, tapi kunci verifikasi diganti
 *
 * @param {number[]} data - Array data asli dari MQTT
 * @param {string} mode - Mode simulasi
 * @returns {number[]} - Data yang sudah diproses sesuai mode
 */
function applyAttack(data, mode) {
    if (mode.startsWith('SYM_COMP')) {
        // Kompresi Simetris: Mensimulasikan noise/kompresi teratur.
        // x_0 ditambah step, x_1 dikurangi step. Ini menjaga nilai cA DWT tetap stabil.
        const symMap = {
            SYM_COMP_05: 0.5,
            SYM_COMP_10: 1.0,
            SYM_COMP_20: 2.0,
        };
        const step = symMap[mode] || 0.5;
        const result = [...data];
        for (let i = 0; i < result.length - 1; i += 2) {
            result[i] += step;
            result[i + 1] -= step;
        }
        return result;

    } else if (mode.startsWith('AWGN')) {
        // AWGN (Symmetrical Noise)
        const awgnVariance = {
            AWGN_VAR_001: 0.01,
            AWGN_VAR_1:   1.0,
            AWGN_VAR_10:  10.0,
        };
        const variance = awgnVariance[mode] || 0.01;
        const sigma = Math.sqrt(variance);
        const result = [...data];
        for (let i = 0; i < result.length - 1; i += 2) {
            const noise = gaussianRandom(0, sigma);
            result[i] += noise;
            result[i + 1] -= noise;
        }
        return result;

    } else if (mode.startsWith('COMPRESS_Q')) {
        // Lossy Compression
        const qMap = {
            COMPRESS_Q50: 50,
            COMPRESS_Q30: 30,
            COMPRESS_Q10: 10,
        };
        const Q = qMap[mode] || 50;
        const step = Math.ceil(CFG.MAX_BPM_REF / Q);
        return data.map(x => Math.round(x / step) * step);

    } else if (mode === 'DELTA_LOSSLESS_O1' || mode === 'DELTA_LOSSLESS_O2') {
        // KOMPRESI LOSSLESS: Delta + Zigzag + Varint → Decompress
        // Pipeline dari TA kolaborasi. Data harus kembali IDENTIK (BER = 0%).
        const orde = (mode === 'DELTA_LOSSLESS_O2') ? 2 : 1;
        const intData = data.map(x => Math.round(x));

        // Compress
        const { compressed, originalSize, compressedSize } = deltaZigzagVarintCompress(intData, orde);
        const ratio = ((1 - compressedSize / originalSize) * 100).toFixed(1);
        console.log(`[DELTA_LOSSLESS] Orde ${orde}: ${originalSize} bytes → ${compressedSize} bytes (hemat ${ratio}%)`);

        // Decompress (harus identik)
        const result = deltaZigzagVarintDecompress(compressed, orde);
        return result;

    } else if (mode === 'DELTA_CORRUPT') {
        // KOMPRESI LOSSLESS + KORUPSI KANAL: Compress → Flip 2 byte → Decompress
        // Mensimulasikan kerusakan data saat transmisi setelah kompresi.
        const intData = data.map(x => Math.round(x));

        // Compress (Orde 1)
        const { compressed } = deltaZigzagVarintCompress(intData, 1);

        // Corrupt: flip 2 random bytes di stream terkompresi
        const corruptedStream = [...compressed];
        if (corruptedStream.length >= 2) {
            const idx1 = Math.floor(Math.random() * corruptedStream.length);
            let idx2 = Math.floor(Math.random() * corruptedStream.length);
            while (idx2 === idx1 && corruptedStream.length > 1) {
                idx2 = Math.floor(Math.random() * corruptedStream.length);
            }
            corruptedStream[idx1] ^= 0xFF;
            corruptedStream[idx2] ^= 0xFF;
            console.log(`[DELTA_CORRUPT] Flipped bytes at index ${idx1} and ${idx2}`);
        }

        // Decompress corrupted stream
        const decoded = deltaZigzagVarintDecompress(corruptedStream, 1);

        // Pastikan panjang output sama dengan input (bisa beda jika varint corrupt)
        const result = [];
        for (let i = 0; i < data.length; i++) {
            result.push(i < decoded.length ? decoded[i] : 0);
        }
        return result;

    } else if (mode === 'ATTACK_BPM') {
        // ATTACK BPM: Tambah 30 ke semua nilai BPM secara konstan
        return data.map(x => x + 30.0);

    } else if (mode === 'ATTACK_BPM_LINEAR') {
        // ATTACK BPM LINEAR: Tambah secara bertahap (+5, +10, +15, dst)
        return data.map((x, i) => x + ((i + 1) * 5));

    } else if (mode === 'ATTACK_KEY') {
        // ATTACK KEY: Data TIDAK diubah (sama seperti NORMAL)
        // Tapi saat verifikasi, kunci hash diganti → expected bits berbeda → INVALID
        return [...data];
    }

    // NORMAL: kembalikan copy data tanpa perubahan
    return [...data];
}

/**
 * Update grafik perbandingan Raw vs Watermarked dan grafik Error.
 *
 * @param {number[]} raw - Data BPM asli (integer, dari ESP32)
 * @param {number[]} watermarked - Data setelah watermarking (float)
 */
function updateCompare(raw, watermarked) {
    if (!compareChart || !raw || raw.length === 0) return;

    // Update data compareChart
    compareChart.data.datasets[0].data = raw;
    compareChart.data.datasets[1].data = watermarked;
    compareChart.update();
    // Hitung metrik perbandingan
    let mseSum = 0;
    let maxErr = 0;
    for (let i = 0; i < raw.length; i++) {
        const diff = raw[i] - watermarked[i];
        mseSum += diff * diff;
        maxErr = Math.max(maxErr, Math.abs(diff));
    }
    const mse = mseSum / raw.length;
    const psnr = mse === 0 ? 100.0 : 20 * Math.log10(CFG.MAX_BPM_REF / Math.sqrt(mse));

    // Update metrik di bawah grafik
    if (dom.compareMetrics) {
        dom.compareMetrics.innerHTML = `<span>MSE: ${mse.toFixed(4)}</span><span>PSNR: ${psnr.toFixed(2)} dB</span><span>Max Error: ${maxErr.toFixed(4)}</span>`;
    }
}

/**
 * Update stat card Computation Time.
 *
 * @param {number} compMs - Waktu komputasi dalam milidetik dari ESP32
 */
function updateCompTime(compMs) {
    // Simpan ke array
    compStats.values.push(compMs);
    if (compStats.values.length > 50) compStats.values.shift(); // Max 50 nilai

    // Hitung statistik
    const sum = compStats.values.reduce((a, b) => a + b, 0);
    compStats.avg = sum / compStats.values.length;
    compStats.max = Math.max(...compStats.values);

    // Update DOM
    dom.compValue.textContent = `${compMs.toFixed(2)} ms`;
    dom.compAvg.textContent = `Avg: ${compStats.avg.toFixed(2)} ms`;
    dom.compMax.textContent = `Max: ${compStats.max.toFixed(2)} ms`;
}

// ===================================================================================
// BAGIAN 10: MQTT CONNECTION
// ===================================================================================

/**
 * Hubungkan ke MQTT broker via WebSocket.
 * Menggunakan MQTT.js yang dimuat via CDN.
 */
function connectMQTT() {
    setMQTT('');  // Status: connecting

    // Generate client ID unik (mencegah konflik jika banyak tab terbuka)
    const id = 'webmon_' + Math.random().toString(16).slice(2, 10);

    // Connect ke broker MQTT via WebSocket
    mqttClient = mqtt.connect(CFG.MQTT_URL, {
        clientId: id,
        clean: true,                              // Session bersih (tidak simpan pesan lama)
        connectTimeout: 10000,                     // Timeout koneksi 10 detik
        reconnectPeriod: 3000,                     // Auto-reconnect setiap 3 detik
    });

    // Event: berhasil connect
    mqttClient.on('connect', () => {
        setMQTT('online');
        mqttClient.subscribe(CFG.MQTT_TOPIC, (err) => {
            if (!err) appendLog('[SYSTEM] MQTT online. Menunggu data ESP32...');
        });
    });

    // Event: error / disconnect / reconnect
    mqttClient.on('error', () => setMQTT('offline'));
    mqttClient.on('close', () => setMQTT('offline'));
    mqttClient.on('reconnect', () => setMQTT(''));

    // Event: menerima pesan MQTT
    mqttClient.on('message', (topic, payload) => {
        const payloadString = payload.toString();

        const p = JSON.parse(payloadString);
        
        // Catat ke paket history untuk export (dengan ms precision)
        const nowMs = new Date();
        const timeStr = `${nowMs.toLocaleTimeString('id-ID', { hour12: false })}.${nowMs.getMilliseconds().toString().padStart(3, '0')}`;
        packetHistory.push({
            time: timeStr,
            type: p.type || 'unknown',
            sizeBytes: payload.length
        });
        // Batasi memori agar tidak jebol (max 100.000 paket)
        if (packetHistory.length > 100000) packetHistory.shift();

        try {
            if (p.type === 'live') {
                // Paket live: update grafik dan BPM
                updateLiveBPM(p.val || 0);

            } else if (p.type === 'secure') {
                // Paket secure: proses verifikasi watermark
                const wmData = p.data || [];         // Data watermarked dari ESP32
                const rawData = p.raw || wmData;     // Data raw (integer BPM) dari ESP32
                const seqNum = p.seq || 0;
                const compMs = p.comp_ms || 0;       // Waktu komputasi ESP32 (ms)

                const processed = applyAttack(wmData, attackMode);  // Terapkan simulasi

                // Parameter: rawData (Asli Ground Truth), wmData (Watermark Murni), processed (Setalah diserang)
                const result = verifyWatermark(rawData, wmData, processed, seqNum, attackMode);
                updateSecure(result, seqNum);         // Update UI watermark

                // Update grafik perbandingan (raw vs watermarked pasca simulasi)
                updateCompare(rawData, processed);

                // Update history tables (menggunakan data pasca simulasi)
                pushBlockHistory(seqNum, result, attackMode);
                pushDataHistory(seqNum, rawData, processed, attackMode, p.dt);

                // Update computation time
                if (compMs > 0) updateCompTime(compMs);
            }
        } catch (e) {
            console.error('[MQTT] Parse error:', e);
        }
    });
}

// ===================================================================================
// BAGIAN 11: EVENT HANDLERS
// ===================================================================================

/**
 * Inisialisasi event handlers untuk interaksi UI.
 */
function initEvents() {
    // --- Radio buttons simulasi serangan ---
    // Fungsi untuk update warna kartu simulasi
    const updateSimCardColor = () => {
        const simCard = document.getElementById('simCard');
        if (simCard) {
            simCard.className = 'card sim-card-' + attackMode.toLowerCase().replace(/_/g, '-');
        }
    };

    document.querySelectorAll('input[name="attackMode"]').forEach(r => {
        r.addEventListener('change', e => {
            attackMode = e.target.value;           // Update mode aktif
            dom.modeBadge.textContent = attackMode; // Update badge

            // Highlight radio button yang aktif
            document.querySelectorAll('.sim-opt').forEach(l => l.classList.remove('active'));
            e.target.closest('.sim-opt').classList.add('active');

            updateSimCardColor();
        });
    });

    // --- Tombol clear log ---
    dom.btnClear.addEventListener('click', () => {
        dom.logArea.textContent = 'Log dibersihkan.\n';
    });

    // --- Tombol Export Log Proses ---
    if (dom.btnDownloadLog) {
        dom.btnDownloadLog.addEventListener('click', () => {
            const textContent = dom.logArea.textContent;
            if (!textContent || textContent.trim() === '') {
                showAlert('Tidak ada log yang bisa diunduh!', 'warning');
                return;
            }

            // Buat blob dan trigger download (file .txt)
            const blob = new Blob([textContent], { type: 'text/plain;charset=utf-8;' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `log_proses_${new Date().toISOString().slice(0, 10)}.txt`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
        });
    }



    // --- Tombol tutup alert ---
    dom.alertClose.addEventListener('click', () => {
        dom.alertBar.style.display = 'none';
    });

    // --- Tombol Export Block Excel (.xlsx) ---
    const btnDownloadBlockCSV = $('btnDownloadBlockCSV');
    if (btnDownloadBlockCSV) {
        btnDownloadBlockCSV.addEventListener('click', () => {
            const rows = dom.blockHistBody.querySelectorAll('tr');
            if (rows.length === 0 || rows[0].classList.contains('empty-row')) {
                showAlert('Tidak ada data blok yang bisa diunduh!', 'warning');
                return;
            }

            // Bangun array data untuk SheetJS (diperkaya dengan watermark bits)
            const data = [['Blok', 'Waktu', 'Status', 'Mode', 'Watermark Expected', 'Watermark Extracted', 'BER (%)', 'PSNR (dB)', 'MSE', 'Keterangan']];

            // Gunakan blockHistory[] yang sudah enriched (lebih akurat dari DOM scraping)
            blockHistory.forEach(entry => {
                data.push([
                    entry.seq,
                    entry.timestamp || '',
                    entry.status,
                    entry.mode,
                    entry.wmExpected || '',
                    entry.wmExtracted || '',
                    parseFloat(entry.ber.toFixed(2)),
                    parseFloat(entry.psnr.toFixed(2)),
                    parseFloat(entry.mse.toFixed(4)),
                    entry.invalidReason || 'Data Otentik',
                ]);
            });

            // Buat workbook dan worksheet
            const wb = XLSX.utils.book_new();
            const ws = XLSX.utils.aoa_to_sheet(data);

            // Auto-width kolom
            ws['!cols'] = data[0].map((_, i) => ({
                wch: Math.max(...data.map(r => String(r[i]).length)) + 2
            }));

            XLSX.utils.book_append_sheet(wb, ws, 'Verifikasi Blok');
            XLSX.writeFile(wb, `blok_verifikasi_DWT_${new Date().toISOString().slice(0, 10)}.xlsx`);
        });
    }

    // --- Tombol Export Data Excel (.xlsx) ---
    if (dom.btnDownloadCSV) {
        dom.btnDownloadCSV.addEventListener('click', () => {
            const rows = dom.dataHistBody.querySelectorAll('tr');
            if (rows.length === 0 || rows[0].classList.contains('empty-row')) {
                showAlert('Tidak ada data yang bisa diunduh!', 'warning');
                return;
            }

            const data = [['Blok', 'Sample', 'Waktu', 'Raw (BPM)', 'Watermarked', 'Selisih', 'Mode']];
            let currentBlock = '';
            let currentMode = '';

            rows.forEach(tr => {
                const tds = tr.querySelectorAll('td');
                if (tds.length === 7) {
                    let blk = tds[0].textContent.replace('#', '').trim();
                    if (blk) currentBlock = blk;
                    else blk = currentBlock;

                    let mode = tds[6].textContent.trim();
                    if (mode) currentMode = mode;
                    else mode = currentMode;

                    data.push([
                        parseInt(blk) || 0,
                        tds[1].textContent.trim(),
                        tds[2].textContent.trim(),
                        parseFloat(tds[3].textContent.trim()) || 0,
                        parseFloat(tds[4].textContent.trim()) || 0,
                        parseFloat(tds[5].textContent.trim()) || 0,
                        mode,
                    ]);
                }
            });

            const wb = XLSX.utils.book_new();
            const ws = XLSX.utils.aoa_to_sheet(data);

            ws['!cols'] = data[0].map((_, i) => ({
                wch: Math.max(...data.map(r => String(r[i]).length)) + 2
            }));

            XLSX.utils.book_append_sheet(wb, ws, 'Data Jantung');
            XLSX.writeFile(wb, `data_jantung_DWT_${new Date().toISOString().slice(0, 10)}.xlsx`);
        });
    }

    // --- Jam digital (update setiap detik) ---
    setInterval(() => {
        dom.clock.textContent = new Date().toLocaleTimeString('id-ID', { hour12: false });
    }, 1000);
}

// ===================================================================================
// BAGIAN 12: INISIALISASI
// ===================================================================================

/**
 * Entry point — dijalankan saat DOM sudah siap.
 */
document.addEventListener('DOMContentLoaded', () => {
    initCharts();                                  // Inisialisasi grafik
    initEvents();                                  // Pasang event handlers
    connectMQTT();                                 // Hubungkan ke MQTT
    dom.clock.textContent = new Date().toLocaleTimeString('id-ID', { hour12: false });  // Set jam awal

    if (window.lucide) lucide.createIcons();       // Buat icon lucide pertama kali

    // Inisialisasi warna kartu simulasi
    const simCard = document.getElementById('simCard');
    if (simCard) {
        simCard.className = 'card sim-card-' + attackMode.toLowerCase().replace(/_/g, '-');
    }
});
