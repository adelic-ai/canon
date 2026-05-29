# forge-core Canonical DSP Borrow-List

## 1. Top-line summary

forge-core's DSP role is narrow but must be accurate: BORROW proven canonical algorithms wholesale (scipy.signal, statsmodels, PyWavelets, mne, astropy) and reserve novelty for organization, never for reinventing the math. Across the six verified families, the count is **6 HAVE** (Welch PSD, Hilbert analytic signal, autocorrelation, rolling/geometric-median baseline, EWMA single-pole IIR), **8 STUB-to-fill** (the empty/docstring-only stubs in `filters.py`, `wavelets.py`, `changepoint.py`, `projection.py`, plus the window pass-through in `spectral.py`), and **~70 MISSING** primitives — the bulk of detection-estimation, time-frequency, decomposition, and multichannel work.

Stub files awaiting implementation:
- `src/forge/ops/filters.py` — docstring-only (names butter/lfilter/savgol/wiener)
- `src/forge/ops/wavelets.py` — docstring-only (names PyWavelets CWT/DWT)
- `src/forge/ops/changepoint.py` — docstring-only (names PELT/BOCPD/CUSUM)
- `src/forge/ops/projection.py` — docstring-only (names PCA/ICA/NMF/UMAP)

## 2. Priority tiers

### T1 — cyber-critical: the beaconing / detection-of-known-signal-in-noise corner

Cyber telemetry is ~90% information-theory, but the C2/beaconing corner is a **detection-estimation** problem: extract a weak periodic carrier from broadband noise. This is the radar/sonar receiver problem, and it is almost entirely MISSING from forge. Highest-value cyber borrows, in order:

1. **CFAR cell-averaging (CA-CFAR)** — MISSING. Adaptive threshold with a closed-form scaling `alpha = N(Pfa^(-1/N) - 1)`; reference-cell mean via cumsum / `scipy.ndimage.uniform_filter1d`. The cumsum route matches the cumsum-vectorisation pattern already in project memory.
2. **OS-CFAR (ordered-statistic CFAR)** — MISSING. `np.partition` sliding-window order statistic; robust to interfering targets / clutter edges where CA-CFAR over-thresholds.
3. **Matched filter (correlation receiver)** — MISSING. `scipy.signal.correlate(method='fft')` against a conjugate-time-reversed template; **prewhiten colored noise via Cholesky** before correlating for the true (optimal-SNR) matched filter.
4. **Goertzel single-bin DFT** — MISSING. Second-order recurrence; cheapest known-frequency carrier test. Use below ~log2(N) target bins; above that prefer rfft.
5. **Lock-in / synchronous detection** — MISSING. Complex-exponential mix + `scipy.signal.sosfiltfilt` low-pass; pulls a known-frequency tone out of noise far below the broadband floor.
6. **Energy detector (radiometer)** — MISSING. Sum-of-squares with `scipy.stats.chi2` (H0) / `scipy.stats.ncx2` (H1) thresholds; band-limited form integrates the existing WelchOp output.
7. **CUSUM sequential change detection** — STUB (`changepoint.py`). Trivial online recurrence (build-fresh); ruptures is offline-only and does NOT provide it.
8. **GLRT / Neyman-Pearson / SPRT / energy / matched-filter** as a coherent detector family — MISSING. Neyman-Pearson LRT is the parent; GLRT (`scipy.stats.chi2` Wilks thresholding) handles unknown amp/phase; SPRT adds Wald two-threshold sequential stopping.

### T1 — EEG-first: the oscillatory substrate (the first consumer)

EEG is genuinely oscillatory and leans hard on spectral / time-frequency / multichannel phase coupling. forge already HAS the analytic-signal and Welch foundations; the gaps are time-frequency resolution and inter-channel connectivity.

Already HAVE: **Welch PSD** (`ops/spectral.py`), **Hilbert analytic signal** (`ops/hilbert.py`, emits amplitude/phase/inst-freq), **autocorrelation** (`ops/correlation.py`).

Highest-value EEG borrows:
1. **STFT / spectrogram** — MISSING. `scipy.signal.ShortTimeFFT` (modern API; legacy `stft`/`spectrogram` deprecated); `mne.time_frequency.tfr_array_stft` for epoched EEG.
2. **Morlet CWT** — STUB (`wavelets.py`). `pywt.cwt` + `mne.time_frequency.tfr_array_morlet` (`n_cycles`). Note `scipy.signal.cwt` was removed in scipy 1.15 — pywt is the right call.
3. **Thomson multitaper PSD (DPSS/Slepian)** — MISSING. `mne.time_frequency.psd_array_multitaper` (natural since mne is a planned dep) or `scipy.signal.windows.dpss` for a lighter build-fresh combiner.
4. **Cross-spectral density + magnitude-squared coherence** — MISSING. `scipy.signal.csd` / `scipy.signal.coherence`; shares Welch machinery, composes with WelchOp. Genuinely new multichannel work (WelchOp is 1-D-only).
5. **PLV / PLI / wPLI** — MISSING. Builds directly on the existing Hilbert phase output: `PLV = |mean(exp(i·dphi))|`. Canonical home `mne_connectivity.spectral_connectivity_epochs`.
6. **ICA** — STUB (`projection.py`). `mne.preprocessing.ICA` (Picard/Infomax + EOG/ECG templates) is the EEG-aware choice over `sklearn.FastICA`.
7. **Zero-phase filtering + notch + band-power filter bank** — STUB (`filters.py`). `scipy.signal.sosfiltfilt` (zero-phase matters for EEG), `iirnotch` at 50/60 Hz line noise, butter+sosfiltfilt+hilbert band-power or `mne.filter.filter_data`.
8. **Cross-frequency coupling (PAC)** — MISSING. `tensorpac` / `pactools`, built on Hilbert outputs.
9. **Surface Laplacian / CSD** — MISSING. `mne.preprocessing.compute_current_source_density` (Perrin spherical splines); needs montage.

### T2 — general substrate: filtering, decomposition, correlation

- **Filter design family** — Butterworth (STUB), Chebyshev I/II, Elliptic, Bessel, FIR windowed-sinc, FIR Parks-McClellan/Remez — all `scipy.signal`, mostly MISSING.
- **Resampling** — decimate, `resample_poly` (polyphase preferred over FFT for time-domain/EEG) — MISSING.
- **Detrending / DC removal** — `scipy.signal.detrend` — MISSING (Welch's per-segment detrend is a pass-through, not a primitive).
- **Cross-correlation (CCF), GCC-PHAT, normalized cross-correlation, cepstrum** — MISSING; land alongside ACFOp in `correlation.py`.
- **Decomposition** — DWT/MRA + wavelet thresholding (STUB), STL, SSA, EMD/EEMD/CEEMDAN, VMD, Robust PCA, OMP, EWT, seasonal decomposition — MISSING.
- **PCA** — STUB (`projection.py`); `sklearn.decomposition.PCA` (KL via `scipy.linalg.eigh` on covariance).
- **Kalman / Wiener filters** — Wiener STUB (`filters.py`), Kalman MISSING; `statsmodels.tsa.statespace` is the best-maintained Kalman home (innovations/standardized residuals out of the box).

### T3 — niche / defer

- **Parametric spectral**: Burg AR PSD, Yule-Walker AR PSD, MUSIC, ESPRIT, Capon/MVDR, Blackman-Tukey — defer unless an EEG/array task pulls them. (`spectrum` library is sparsely maintained — prefer statsmodels AR or build-fresh on `numpy.linalg.eigh`.)
- **Exotic time-frequency**: Wigner-Ville, reassignment/synchrosqueezing (`ssqueezepy`), Stockwell, chirp-Z/zoom-FFT, Hilbert-Huang.
- **Array processing / beamforming**: LCMV, DICS, delay-and-sum DOA, array-MUSIC, CSP, CCA, Riemannian classification, Granger/DTF/PDC, imaginary coherency, shrinkage covariance, Lomb-Scargle. EEG-adjacent but second-wave; Lomb-Scargle (`astropy.timeseries.LombScargle`) earns earlier priority if irregularly-sampled telemetry appears.
- **Reference/benchmark, not runtime**: Cramer-Rao lower bound — fits the meta/validation layer, not the op pipeline.

## 3. Per-family tables

forge action legend: **PORT** = code already exists, migrate it; **BORROW** = thin typed wrapper over a named library function; **BUILD** = build-fresh (no clean library drop-in).

### Spectral estimation

<<<
Periodogram (Schuster)        | BORROW scipy.signal.periodogram   | both     | raw single-shot PSD                       | high variance, never consistent — for tests/baselines only
Welch's method                | PORT (HAVE, spectral.py)          | both     | variance-reduced PSD via segment-avg      | already handles real one-sided / complex two-sided; clamps nperseg
Bartlett's method             | BORROW scipy.signal.welch         | both     | Welch w/ boxcar, noverlap=0               | express via WelchOp kwargs; no dedicated op warranted
Thomson multitaper (DPSS)     | BORROW mne psd_array_multitaper   | EEG      | low-variance PSD via Slepian tapers       | NW/K bandwidth-vs-variance tradeoff; dpss via scipy for light path
Burg AR PSD                   | BUILD on statsmodels burg coeffs  | EEG      | high-res short-segment parametric PSD     | statsmodels gives coeffs only — build PSD; spectrum.pburg unmaintained
Yule-Walker AR PSD            | BUILD on statsmodels yule_walker  | EEG      | parametric PSD via ACF→coeffs             | coeffs only — build PSD; biased vs unbiased ACF choice matters
MUSIC                         | BUILD on numpy.linalg.eigh        | niche    | sinusoid freqs in noise (subspace)        | needs model order (# signals); spectrum.pmusic sparsely maintained
ESPRIT                        | BUILD on scipy.linalg eig/svd     | niche    | rotational-invariance freq estimation     | out of scope unless array task pulls
Lomb-Scargle periodogram      | BORROW astropy LombScargle        | cyber    | PSD for irregularly-sampled data          | prefer astropy (generalized LS + FAP) over scipy.signal.lombscargle
Capon / MVDR                  | BUILD on numpy.linalg.inv         | niche    | min-variance distortionless PSD           | needs covariance inverse; diagonal-load for stability
Blackman-Tukey                | BUILD (FFT of windowed ACF)       | both     | PSD via windowed autocorrelation          | can feed directly from existing ACFOp; lag-window choice = bias/var
Spectrogram / STFT            | BORROW scipy ShortTimeFFT         | EEG      | time-resolved PSD                         | use ShortTimeFFT class; legacy stft/spectrogram deprecated
CSD + MS coherence            | BORROW scipy.signal.csd/coherence | EEG      | two-input cross-spectrum + coherence      | shares Welch machinery; coherence needs segment-avg or =1 trivially
Peak picking on PSD           | BORROW scipy.signal.find_peaks    | both     | locate spectral lines w/ prominence/width | tune prominence/width; zero usage in repo today
>>>

### Time-frequency analysis

<<<
STFT / Spectrogram            | BORROW scipy ShortTimeFFT          | EEG   | time-resolved spectrum               | ShortTimeFFT API; mne.tfr_array_stft for epochs
CWT (Morlet)                  | BORROW pywt.cwt / mne morlet (STUB)| EEG   | adaptive time-freq, log-freq         | scipy.signal.cwt REMOVED in 1.15 — use pywt; n_cycles tradeoff
DWT / Wavelet Packet          | BORROW pywt (STUB, wavelets.py)    | both  | dyadic multiresolution               | boundary mode + level choice; pywt.wavedec/swt/WaveletPacket
Hilbert analytic signal       | PORT (HAVE, hilbert.py)            | EEG   | inst amplitude/phase/frequency       | already vectorised per-row, rejects complex input
Hilbert-Huang (EMD+Hilbert)   | BORROW PyEMD                        | EEG   | data-driven nonstationary modes      | EMD mode-mixing — prefer EEMD/CEEMDAN; no scipy equiv
Wigner-Ville Distribution     | BORROW tftb / BUILD                 | niche | high-res quadratic TFR               | cross-term interference — needs smoothing
Multitaper spectrogram        | BORROW mne tfr_array_multitaper    | EEG   | time-resolved low-variance PSD       | DPSS via scipy.signal.windows.dpss
Reassignment/Synchrosqueezing | BORROW ssqueezepy                  | niche | sharpened TFR ridges                 | ssq_cwt/ssq_stft canonical
Filter-bank / band-power      | BUILD butter+sosfiltfilt+hilbert(STUB)| EEG| per-band envelope power              | zero-phase mandatory; or mne.filter.filter_data
Cross-frequency coupling (PAC)| BORROW tensorpac / pactools        | EEG   | phase-amplitude coupling             | surrogate stats needed; builds on Hilbert outputs
Goertzel                      | BUILD (2nd-order recurrence)       | cyber | single-bin DFT, known freq           | no scipy.signal.goertzel; cheapest known-tone test
Chirp-Z / Zoom-FFT            | BORROW scipy.signal.czt/zoom_fft   | both  | high-res zoom on freq band           | scipy.signal.CZT/zoom_fft correct
Stockwell (S-transform)       | BORROW stockwell / BUILD           | niche | freq-dependent-window TFR            | FFT-based build-fresh viable
>>>

### Correlation & matched filtering

<<<
Autocorrelation (ACF)         | PORT (HAVE, correlation.py)        | both  | self-similarity / periodicity        | uses numpy.correlate (Wiener-Khinchin), normalized [0]=1; complex-safe
Cross-correlation (CCF)       | BORROW scipy.signal.correlate      | both  | lag alignment between two signals     | pair with correlation_lags; lands beside ACFOp
Matched filter                | BUILD on scipy.signal.correlate    | cyber | optimal weak-signal detection        | conjugate-time-reverse template + WHITEN colored noise
CSD + MS coherence            | BORROW scipy.signal.csd/coherence  | EEG   | linear coupling vs frequency         | composes with WelchOp machinery
GCC-PHAT                      | BUILD on numpy.fft                  | both  | robust time-delay estimation         | whitened cross-spectrum, ~10 lines; pyroomacoustics ref
Normalized cross-correlation  | BUILD (cumsum sliding mean/var)    | both  | template-match coefficient           | numerically-stable via cumsum; skimage match_template for 2D
Cepstrum (real/complex)       | BUILD on scipy.fft                  | both  | echo/pitch/periodicity in log-spec   | complex needs unwrap + linear-phase removal
Phase Locking Value (PLV)     | BUILD on existing Hilbert phase    | EEG   | phase synchronization across chans   | |mean(exp(i·dphi))|; mne_connectivity alt
Goertzel                      | BUILD (recursion / lfilter biquad) | cyber | single-bin energy at known freq      | no scipy.signal.goertzel
Lock-in detection             | BUILD (mix + low-pass)             | cyber | extract tone buried in noise         | composes with planned filters.py low-pass
Partial/multiple coherence    | BUILD on scipy.signal.csd matrix   | EEG   | coupling controlling for 3rd chans   | depends on csd/coherence landing first
Wiener filter                 | BORROW scipy.signal.wiener (STUB)  | both  | LMMSE denoise / deconvolution        | scipy.wiener=SPATIAL adaptive; freq-domain LMMSE is build-fresh; in filters.py
>>>

### Digital filtering & filter banks

<<<
Butterworth IIR               | BORROW scipy.signal.butter (STUB)  | both  | maximally-flat passband filter       | sos + sosfiltfilt + buttord for order
Chebyshev I / II              | BORROW scipy cheby1/cheby2         | both  | steeper rolloff w/ ripple            | cheb1ord/cheb2ord; ripple-vs-rolloff
Elliptic (Cauer)              | BORROW scipy.signal.ellip          | both  | steepest rolloff, ripple both bands  | ellipord; sharpest but most phase distortion
Bessel / Thomson              | BORROW scipy.signal.bessel         | both  | maximally-flat group delay           | norm= choice (phase/mag/delay) matters
FIR windowed-sinc             | BORROW scipy.signal.firwin/firwin2 | both  | linear-phase FIR                     | window-vs-transition-width tradeoff
FIR Parks-McClellan/Remez     | BORROW scipy.signal.remez/firls    | both  | equiripple optimal FIR               | band edges + weights; convergence caveats
Zero-phase (filtfilt)         | BORROW scipy.signal.sosfiltfilt    | EEG   | no phase distortion                  | sosfiltfilt over filtfilt; doubles effective order
Savitzky-Golay                | BORROW scipy.signal.savgol_filter  | both  | polynomial smoothing w/ derivatives  | window/polyorder tradeoff
Window functions (DPSS etc)   | BORROW scipy.signal.windows (STUB) | both  | tapering / leakage control           | DPSS needed for multitaper; currently only hann pass-through
Decimation                    | BORROW scipy.signal.decimate       | both  | anti-alias + downsample              | IIR vs FIR ftype; apply before subsample
Polyphase resampling          | BORROW scipy resample_poly         | EEG   | rational-factor resample             | resample_poly over FFT resample (no edge-wrap)
Perfect-reconstruction/QMF    | BORROW pywt / BUILD (STUB)         | both  | critically-sampled filter banks      | pywt for DWT realization; M-channel = build-fresh
Wiener filter                 | BUILD (spectral, from Welch)(STUB) | both  | optimal LMMSE denoise                | feed existing Welch PSD; spatial form = scipy.wiener
Kalman filter (linear)        | BORROW statsmodels statespace      | both  | recursive state estimation           | statsmodels best-maintained; pykalman unmaintained
Hilbert / analytic signal     | PORT (HAVE, hilbert.py)            | EEG   | envelope + inst phase                 | confirmed scipy.signal.hilbert
Notch / comb filter           | BORROW scipy iirnotch/iircomb      | EEG   | line-noise removal                   | 50/60 Hz EEG line removal; Q-factor choice
Median / Hampel               | PORT (HAVE, baselines.py)          | both  | impulse/outlier rejection            | rolling median PRESENT (ndimage); Hampel/MAD variant NOT — add
DC removal / detrend          | BORROW scipy.signal.detrend        | both  | remove constant/linear trend         | Welch detrend= is pass-through, not a primitive
EWMA / exp smoothing          | PORT (HAVE, baselines.py)          | both  | single-pole IIR low-pass             | _ewma_per_row, complex-closed; missed by researcher
Weiszfeld geometric median    | PORT (HAVE, baselines.py)          | both  | robust complex-field median          | complex generalization of medfilt; missed by researcher
>>>

### Detection & estimation theory

<<<
Matched filter                | BUILD on scipy.signal.correlate    | cyber | max-SNR known-template detection     | prewhiten colored noise (Cholesky); no prewhitener exists yet
CA-CFAR                       | BUILD (cumsum / uniform_filter1d)  | cyber | adaptive threshold, const Pfa        | alpha=N(Pfa^(-1/N)-1); over-thresholds near clutter edges
OS-CFAR                       | BUILD (np.partition sliding)       | cyber | CFAR robust to interferers           | k-th order stat choice; slower than CA
Goertzel single-bin DFT       | BUILD (2nd-order recurrence)       | cyber | known-frequency energy               | few bins beats rfft; above ~log2(N) prefer fft
Lock-in / synchronous det     | BUILD (mix + sosfiltfilt)          | cyber | weak tone at known freq+phase        | needs reference phase; low-pass bandwidth = integration time
GLRT                          | BUILD per-model (scipy.stats.chi2) | both  | composite hypothesis test            | unknown amp/phase → periodogram-bin/MF-magnitude test (Kay II)
Energy detector (radiometer)  | BUILD (sum-sq + chi2/ncx2)         | cyber | unknown-signal presence              | chi2 (H0)/ncx2 (H1); band form integrates WelchOp
CUSUM                         | BUILD (recurrence) (STUB)          | cyber | sequential change detection          | ruptures is OFFLINE only — does NOT provide online CUSUM
Neyman-Pearson LRT            | BUILD per-model                    | both  | optimal fixed-sample test            | parent of energy/MF detectors; roc_curve for empirical ROC
SPRT                          | BUILD (running log-LR + Wald)      | both  | sequential test, min samples         | A=log((1-β)/α), B=log(β/(1-α)); Wald 1945
Periodogram/Schuster test     | BUILD (rfft + Fisher g-test)       | cyber | periodicity significance             | Fisher g closed-form Pfa; astropy LS for uneven sampling
Kalman innovations detector   | BORROW statsmodels statespace      | both  | residual-based anomaly               | standardized residuals as hook; pykalman unmaintained
Cramer-Rao lower bound        | BUILD (Fisher info per model)      | meta  | estimator-accuracy benchmark         | meta/validation layer, NOT runtime; numdifftools for numeric FI
CFAR matched-filter envelope  | BUILD (compose hilbert+MF+CFAR)    | cyber | non-coherent weak-signal detection   | composite of 3 missing parts; envelope=|analytic| exists
Burg AR line detection        | BUILD on statsmodels AR / MUSIC    | EEG   | parametric narrowband detection      | spectrum lib unmaintained — statsmodels/numpy.linalg.eigh
>>>

### Signal decomposition

<<<
Wavelet MRA (DWT)             | BORROW pywt.wavedec/mra/swt (STUB) | both  | additive multiresolution split       | pywt.mra (>=1.3); lattice.py M-band Haar is NOT general MRA
Wavelet thresholding denoise  | BORROW skimage denoise_wavelet(STUB)| both | sparse-coeff denoising               | BayesShrink/VisuShrink in skimage; SureShrink = build-fresh
STL                           | BORROW statsmodels STL/MSTL        | both  | seasonal-trend-residual split        | period required; MSTL for multi-seasonal
Singular Spectrum Analysis    | BUILD (scipy svd+hankel)           | both  | trend/oscillation/noise via SVD      | window L + grouping; pyts/pymssa alts
EMD / EEMD / CEEMDAN          | BORROW PyEMD                        | EEG   | data-driven IMF decomposition        | mode-mixing → prefer EEMD/CEEMDAN
VMD                           | BORROW vmdpy                        | EEG   | variational mode decomposition       | K modes + alpha bandwidth; Dragomiretskiy-Zosso
Robust PCA (PCP)             | BUILD (scipy svd, IALM)            | both  | low-rank + sparse split              | SVT soft-threshold; PyPI rpca pkgs thin
Matching Pursuit / OMP        | BORROW sklearn OMP/SparseCoder     | EEG   | sparse dictionary decomposition      | Gabor-dictionary EEG variant = build-fresh
Empirical Wavelet Transform   | BORROW ewtpy.EWT1D                  | niche | adaptive Fourier-boundary wavelets   | boundary detection = build-fresh on scipy.fft
Seasonal/classical decompose  | BORROW statsmodels seasonal_decomp | both  | additive/multiplicative split        | DeltaOp is lag-1 only; not seasonal
ICA                           | BORROW mne.preprocessing.ICA (STUB)| EEG   | source separation / artifact removal | mne (Picard/Infomax) over sklearn for EEG
M-band Haar detail (Δp F)     | PORT (HAVE, lattice.py)            | both  | dyadic Haar detail energy            | cross-prime hypothesis FALSIFIED — treat as Haar detail only
>>>

### Multichannel & spatial

<<<
PCA / KL transform            | BORROW sklearn PCA (STUB)          | both  | decorrelating projection             | scipy.linalg.eigh on covariance = KL; whiten=True
ICA                           | BORROW mne.ICA / sklearn FastICA   | EEG   | independent source separation        | mne for EEG artifacts; NEW DEP
MS coherence (Welch)          | BORROW scipy.signal.coherence      | EEG   | linear coupling vs freq              | WelchOp is 1-D-only — genuinely new multichannel
PLV / PLI / wPLI              | BUILD on Hilbert / mne_connectivity| EEG   | phase synchronization                | wPLI volume-conduction-robust; NEW DEP for mne route
CSP                           | BORROW mne.decoding.CSP             | EEG   | discriminative spatial filters       | scipy.linalg.eigh generalized eig on 2 class covs
Cross-spectral matrix (CSDM)  | BORROW mne csd_multitaper           | EEG   | Hermitian cross-spectrum matrix      | scipy.signal.csd pairwise for assembly; NEW DEP
Granger causality             | BORROW statsmodels grangercausality| EEG   | directed linear influence            | strictly bivariate — conditional GC = build on VAR
DTF / PDC                     | BUILD on statsmodels VAR / scot    | EEG   | directed connectivity in freq        | H(f)/A(f) from VAR coeffs; scot over connectivipy
LCMV beamformer               | BORROW mne make_lcmv / BUILD MVDR  | both  | spatial-filter source/array          | array MVDR = R^-1 a / a^H R^-1 a (few lines)
DICS beamformer               | BORROW mne make_dics                | EEG   | freq-domain coherent-source imaging  | consumes CSD; NEW DEP
Delay-and-sum DOA (Bartlett)  | BUILD (numpy steering vectors)     | niche | conventional beamform direction      | no scipy fn; pyroomacoustics for acoustic
MUSIC array DOA               | BUILD (eigh + steering scan)       | niche | subspace direction-of-arrival        | needs # sources; mne RAP-MUSIC is different problem
GCC-PHAT TDOA                 | BUILD on scipy correlate + PHAT    | both  | time-delay between channels          | ACFOp is auto-only; PHAT weighting build-fresh
Riemannian covariance class.  | BORROW pyriemann                    | EEG   | SPD-matrix tangent-space classify    | scipy.linalg logm/expm; NEW DEP
Imaginary coherency (ImCoh)   | BUILD on scipy.signal.csd          | EEG   | leakage-robust connectivity          | Im of normalized cross-spectrum; mne_connectivity alt
CCA                           | BORROW sklearn CCA                  | EEG   | cross-set canonical correlation      | FBCCA/TRCA (SSVEP) = build-fresh
Shrinkage covariance          | BORROW sklearn LedoitWolf/OAS      | both  | regularized covariance estimate      | SHARED base for CSP/LCMV/MUSIC/Riemannian — land early
Surface Laplacian / CSD       | BORROW mne compute_current_source_density | EEG | reference-free spatial sharpening | Perrin spherical splines; needs montage
>>>

## 4. The detection-estimation deep-dive

The cyber beaconing/C2 problem is structurally the radar problem: **detect a weak periodic carrier embedded in broadband noise, at a controlled false-alarm rate.** The radar→cyber analogy buys forge a 70-year-old, mathematically optimal toolkit instead of ad-hoc thresholds. Each primitive occupies a distinct point in the (known vs unknown signal parameters) × (coherent vs non-coherent) × (fixed vs adaptive threshold) space.

**CFAR (cell-averaging vs ordered-statistic).** CFAR is the *threshold* layer, not the detector. The signal statistic (matched-filter output, periodogram, or energy) is computed first; CFAR sets the decision threshold *adaptively from the local noise floor* so the false-alarm probability stays constant even as the background drifts. In cyber, the "background" is the host's normal connection-rate baseline, which is non-stationary across time-of-day and host role — exactly the drift CFAR is built for.
- **CA-CFAR**: threshold = `alpha × mean(reference cells)`, `alpha = N(Pfa^(-1/N) - 1)`. Cheap (cumsum, matching the project's cumsum-vectorisation pattern), optimal in homogeneous noise. It over-thresholds (misses) when a second beacon or a clutter edge sits inside the reference window — i.e. when two C2 channels run concurrently or traffic regime changes mid-window.
- **OS-CFAR**: replaces the mean with the k-th order statistic of the reference cells (`np.partition`). Robust precisely where CA-CFAR fails — interfering targets and clutter edges — at higher compute cost. For multi-beacon hosts, OS-CFAR is the safer default.

**Matched filter (correlation receiver).** The provably max-SNR detector when the signal *shape* is known. Cross-correlate the data with the conjugate-time-reversed template (`scipy.signal.correlate(method='fft')`). In cyber, the "template" is a known beacon inter-arrival pattern (fixed-interval, jittered, or staged). Critical caveat the bare correlate misses: the matched filter is only optimal in *white* noise — colored background traffic must be **prewhitened (Cholesky on the noise covariance)** first. forge has no prewhitener yet (`filters.py` is a stub), so this is a two-part build.

**Goertzel.** A single-bin DFT via a second-order recurrence — the matched filter specialized to a *pure known frequency* with minimal compute. For testing "is there a beacon at exactly this period?" across a handful of candidate intervals, Goertzel beats a full rfft; above ~log2(N) candidate bins, switch to FFT. This is the cheapest entry point for known-period beacon hunting.

**Lock-in detection (synchronous/quadrature demodulation).** Mixes the signal with a complex exponential at the carrier frequency and low-passes (`scipy.signal.sosfiltfilt`). This pulls a tone *arbitrarily far below* the broadband noise floor by integrating coherently — the low-pass bandwidth sets the integration time and thus the noise rejection. In cyber, lock-in extracts a slow, deeply-buried periodic exfil/heartbeat signal that energy detection would never see, *provided the period is known or scanned*. It is the coherent counterpart to the energy detector's non-coherent radiometry.

Together these form a ladder by prior knowledge: **energy detector** (signal unknown) → **Goertzel/lock-in** (frequency known) → **matched filter** (full shape known), with **GLRT** bridging the unknown-amplitude/phase gaps and **CFAR** sitting on top of all of them as the adaptive-threshold layer. **SPRT/CUSUM** add the sequential (minimum-samples / online change) dimension.

## 5. Sequencing recommendation

Build order is **EEG-first**, so the EEG oscillatory substrate leads; the detection-estimation primitives are deliberately structured so that the EEG borrows *also lay the foundations* the cyber beaconing corner needs later.

**Wave 1 — EEG core (fill the stubs, port what exists).**
1. `filters.py`: Butterworth + `sosfiltfilt` (zero-phase) + `iirnotch` + band-power filter bank. Zero-phase + line-noise removal is the EEG entry tax. *This wave also delivers the low-pass that lock-in detection and the matched-filter prewhitener will consume.*
2. STFT (`ShortTimeFFT`) + Morlet CWT (`wavelets.py`, pywt/mne) — time-frequency for EEG. *STFT's per-bin machinery is the same periodogram-bin test the Schuster/GLRT beacon detector reduces to.*
3. PORT confirmations: Welch, Hilbert, ACF, rolling-median, EWMA already HAVE — wire them into the EEG Surface, no new code.

**Wave 2 — EEG connectivity + multitaper.**
4. CSD + magnitude-squared coherence (`scipy.signal.csd/coherence`) — extends WelchOp to two-input. *This is the cross-spectral primitive the cyber two-channel correlation work reuses.*
5. PLV/PLI/wPLI built on the existing Hilbert phase output (cheap, high-value, no new dep for the build-fresh route).
6. Thomson multitaper PSD (`mne psd_array_multitaper`) + DPSS windows in `filters.py`. *DPSS is the shared dependency for both the multitaper spectrogram and any future array/detection multitaper.*
7. ICA (`projection.py`, `mne.preprocessing.ICA`) — artifact removal; PCA lands alongside as the cheaper covariance-EVD sibling.

**Wave 3 — cyber beaconing corner (the detection-estimation family).** Now the filtering, FFT, and cross-spectral foundations from Waves 1–2 are in place, so these are mostly thin composites:
8. **Goertzel** + **energy detector (radiometer)** — cheapest known-frequency and unknown-signal tests; energy detector integrates the existing WelchOp output directly.
9. **CA-CFAR then OS-CFAR** — the adaptive-threshold layer (cumsum / `np.partition`); the single highest-value cyber borrow.
10. **Matched filter** + Cholesky prewhitener — reuses Wave-1 filtering; the prewhitener is the one genuinely new sub-part.
11. **Lock-in detection** — composes Wave-1 low-pass with complex-exponential mixing.
12. **CUSUM** (`changepoint.py` stub) + **SPRT** — sequential/online layer; trivial recurrences.
13. **GLRT / Neyman-Pearson** wrapper unifying the above as a coherent detector family (`scipy.stats` thresholds, `roc_curve` for ROC).

**Defer to pull (Wave 4+):** parametric spectral (Burg/Yule-Walker/MUSIC/Capon), exotic TFR (Wigner-Ville, synchrosqueezing, Stockwell, HHT), array/beamforming (LCMV/DICS/DOA/CSP/Granger/DTF-PDC), decomposition beyond DWT (SSA/EMD/VMD/RPCA/EWT/STL), Lomb-Scargle, Cramer-Rao bound (meta/validation layer). Build each only when a concrete EEG or cyber task pulls it; do not pre-build the niche tier.

**Shared-dependency note:** land **DPSS windows** (Wave 2) and **shrinkage covariance** (`sklearn LedoitWolf/OAS`) early if the array/Riemannian tier is on the horizon — both are base primitives that CSP, LCMV, MUSIC, and Riemannian classification all depend on, and building them once avoids four duplicate implementations.
