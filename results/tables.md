# Results

Runtime: 506.7 s. All numbers are on the held-out test split (servers never seen in training).

## Data

| split | updates | attack updates |
|---|---|---|
| val | 440 | 177 |
| train | 2061 | 751 |
| test | 438 | 246 |

## Detector (per update)

| model | precision | recall | F1 | FPR | recall at FPR<=5% | recall at FPR<=10% | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|---|---|
| Change-pair step head (ours) | 0.9377 | 0.9797 | 0.9583 | 0.0833 | 0.9228 | 0.9919 | 0.988 | 0.9899 |
| New text only (embeddings) | 0.7538 | 0.7967 | 0.7747 | 0.3333 | 0.2602 | 0.4431 | 0.7843 | 0.8243 |
| TF-IDF of new text | 0.9398 | 0.9512 | 0.9455 | 0.0781 | 0.9065 | 0.9593 | 0.9755 | 0.9791 |
| TF-IDF of added text | 0.9211 | 0.9959 | 0.957 | 0.1094 | 0.813 | 0.9837 | 0.9805 | 0.9826 |
| Cumulative head (ours, label: attack added since approval) | 0.9742 | 0.9228 | 0.9478 | 0.0312 | 0.935 | 0.9715 | 0.9839 | 0.9874 |

Precision, recall, F1 and FPR at threshold 0.5.

Detector settings chosen on validation (recall at FPR<=5%): step head = tfidf_features_w10, C=0.5; cumulative head = tfidf_features_w10, C=0.5.

## Held-out real-world false positives (273 real description changes, 140 tools, 10 fresh community MCP repos (git history); never used to fit or tune)

| detector | FPR at 0.5 | FPR at val FPR<=5% threshold | same, averaged per repo | threshold | mean risk |
|---|---|---|---|---|---|
| Change-pair step head (ours) | 2.9% | 1.5% | 2.6% | 0.7017 | 0.0859 |
| New text only (embeddings) | 45.1% | 22.0% | 11.7% | 0.9847 | 0.4389 |
| TF-IDF of new text | 5.1% | 1.8% | 1.0% | 0.6203 | 0.2899 |
| TF-IDF of added text | 7.0% | 1.5% | 1.2% | 0.6604 | 0.2763 |
| Ablation: embeddings instead of TF-IDF, same training data | 13.6% | 10.6% | 11.8% | 0.7166 | 0.1632 |
| Ablation: chosen model, no real changes in training | 30.8% | 20.5% | 33.9% | 0.6864 | 0.349 |

### Robustness on the test servers (same thresholds; 42 softened, 184 reworded attack updates)

| detector | attacks caught | legitimate flagged | softened caught | reworded: as written | reworded: reworded |
|---|---|---|---|---|---|
| Change-pair step head (ours) | 92.3% | 4.7% | 100.0% | 93.5% | 82.6% |
| New text only (embeddings) | 55.7% | 15.6% | 50.0% | 58.1% | 51.6% |
| TF-IDF of new text | 90.6% | 4.2% | 85.7% | 90.8% | 82.1% |
| TF-IDF of added text | 88.6% | 6.8% | 97.6% | 90.2% | 72.8% |
| Ablation: embeddings instead of TF-IDF, same training data | 74.0% | 5.2% | 81.0% | 78.8% | 64.1% |
| Ablation: chosen model, no real changes in training | 86.6% | 4.2% | 100.0% | 88.0% | 87.0% |

Development set (53 changes from the official servers, part of training; 5-fold grouped cross-validation): FPR at 0.5 = 9.4%.

Gateway policies on the real histories (all legitimate):

| policy | false-block rate | review burden |
|---|---|---|
| Hash pinning | 6.6% | 100.0% |
| Classifier (new text only) | 4.0% | 59.5% |
| Change-pair + threshold | 0.0% | 1.5% |
| Change-pair + history rule | 0.0% | 1.5% |
| Change-pair + cumulative threshold (ours) | 0.0% | 0.0% |
| Change-pair + MDP (ours) | 0.5% | 3.7% |

### Recall / FPR by attack style

| style | n | change-pair recall | new-only recall |
|---|---|---|---|
| original | 62 | 0.9804 | 0.8824 |
| softened | 58 | 1.0 | 0.7857 |
| templated | 171 | 0.9739 | 0.7712 |

### By change type

| change type | n | change-pair flagged | new-only flagged |
|---|---|---|---|
| bundle | 57 | 1.8% | 31.6% |
| default_value | 17 | 0.0% | 23.5% |
| deprecation | 13 | 0.0% | 38.5% |
| doc_expansion | 12 | 0.0% | 33.3% |
| error_note | 12 | 0.0% | 50.0% |
| example | 7 | 0.0% | 28.6% |
| malicious_one_shot | 36 | 100.0% | 80.6% |
| malicious_slow_decomposed | 153 | 97.4% | 77.1% |
| malicious_slow_split | 57 | 98.2% | 86.0% |
| optional_param | 4 | 0.0% | 0.0% |
| param_docs | 10 | 0.0% | 30.0% |
| process_note | 11 | 81.8% | 63.6% |
| rewording | 7 | 0.0% | 42.9% |
| security_note | 13 | 0.0% | 7.7% |
| tool_reference | 6 | 100.0% | 66.7% |
| usage_guidance | 14 | 0.0% | 28.6% |
| version_note | 9 | 0.0% | 33.3% |

(For malicious types the share flagged is recall; for benign types it is the false-positive rate.)

Hard negatives (legitimate but suspicious-sounding official tools such as Fetch and get-env), scored out-of-fold: n=54 updates, FPR change-pair 7.4%, new-only 11.1%.

## Feature ablation (detector, per update)

| features | F1 | recall | FPR | ROC-AUC |
|---|---|---|---|---|
| full | 0.8145 | 0.7317 | 0.0833 | 0.9106 |
| no_embed_added | 0.7692 | 0.7317 | 0.2188 | 0.8133 |
| no_embed_diff | 0.8608 | 0.8171 | 0.1042 | 0.9276 |
| no_drift | 0.827 | 0.748 | 0.0781 | 0.9127 |
| no_scope | 0.8109 | 0.7236 | 0.0781 | 0.9091 |
| no_flags | 0.8163 | 0.7317 | 0.0781 | 0.9045 |
| flags_and_numeric_only | 0.7794 | 0.8618 | 0.4479 | 0.7864 |

## Generalization

| held out | F1 | recall | FPR | ROC-AUC |
|---|---|---|---|---|
| paradigm Template-1 | 0.9365 | 0.9516 | 0.0843 | 0.9821 |
| paradigm Template-2 | 0.9442 | 0.9317 | 0.086 | 0.978 |
| paradigm Template-3 | 0.9163 | 0.8708 | 0.0678 | 0.9774 |
| template phrasings | 0.8315 | 0.7117 | 0.0 | 0.9154 |

## Sequence-level detection (ROC-AUC, attack histories vs benign histories)

| attack type | attack seqs | max per-step risk | final cumulative risk (d0 -> new) | new text only |
|---|---|---|---|---|
| all | 101 | 0.9994 | 0.9945 | 0.8533 |
| one_shot | 22 | 0.999 | 0.999 | 0.8733 |
| slow_split | 19 | 1.0 | 1.0 | 0.9351 |
| slow_decomposed | 28 | 1.0 | 1.0 | 0.8731 |
| mixed | 32 | 0.9987 | 0.9834 | 0.7736 |

## Gateway policies (per sequence), all attack strategies seen in training

Costs: miss (completed attack)=100.0, false block=10.0, review=2.0, reviewer error=0.05. Averaged over reviewer-error seeds; brackets are bootstrap 95% CIs over test sequences.

| policy | ASR | FBR | review burden | detection delay | stopped before payload | cost/update |
|---|---|---|---|---|---|---|
| No protection | 100.0% | 0.0% | 0.0% | n/a | 0.0% | 23.06 |
| Hash pinning | 2.0% [0.0%, 4.8%] | 6.5% [2.1%, 8.4%] | 100.0% [100.0%, 100.0%] | 0.04 | 62.0% | 3.12 [2.22, 3.94] |
| Classifier (new text only) | 9.5% [3.8%, 14.2%] | 3.5% [0.6%, 5.2%] | 64.3% [55.8%, 72.5%] | 0.11 | 54.9% | 4.62 [2.68, 5.99] |
| Change-pair + threshold | 0.0% [0.0%, 1.0%] | 1.6% [0.0%, 3.1%] | 14.4% [10.4%, 18.5%] | 0.15 | 61.2% | 0.39 [0.26, 0.70] |
| Change-pair + history rule | 0.0% [0.0%, 1.0%] | 1.6% [0.0%, 3.1%] | 14.4% [10.4%, 18.5%] | 0.15 | 61.2% | 0.39 [0.26, 0.70] |
| Change-pair + cumulative threshold (ours) | 0.2% [0.0%, 1.0%] | 1.6% [0.0%, 3.5%] | 6.2% [3.8%, 9.1%] | 0.34 | 58.4% | 0.28 [0.12, 0.52] |
| Change-pair + MDP (ours) | 1.2% [0.0%, 3.3%] | 1.1% [0.0%, 3.0%] | 6.6% [4.0%, 9.4%] | 0.14 | 61.0% | 0.60 [0.12, 1.33] |

Tuned on the policy-fit set: threshold=[0.7, 0.95], new-only threshold=[0.05, 1.01], history rule theta=1.01, MDP risk bins=[0.1, 0.7]. Value iteration converged in 30 iterations.

Paired bootstrap, MDP minus baseline (95% CI; share of resamples where the MDP is lower):

| baseline | ASR diff | FBR diff | review diff | cost diff | P(MDP cost lower) |
|---|---|---|---|---|---|
| Change-pair + threshold | [+0.000, +0.032] | [-0.017, +0.016] | [-0.127, -0.035] | [-0.289, +0.932] | 0.327 |
| Change-pair + history rule | [+0.000, +0.032] | [-0.017, +0.016] | [-0.127, -0.035] | [-0.289, +0.932] | 0.327 |
| Change-pair + cumulative threshold (ours) | [+0.000, +0.032] | [-0.022, +0.015] | [-0.037, +0.042] | [-0.108, +1.055] | 0.191 |
| Classifier (new text only) | [-0.133, -0.021] | [-0.044, +0.011] | [-0.666, -0.485] | [-5.433, -2.055] | 1.0 |

Attack success rate by sequence type (benign row shows false-block rate):

| type | n | Hash pinning | Classifier (new text only) | Change-pair + threshold | Change-pair + history rule | Change-pair + cumulative threshold (ours) | Change-pair + MDP (ours) |
|---|---|---|---|---|---|---|---|
| one_shot | 22 | 6.4% | 10.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| slow_split | 19 | 1.1% | 1.1% | 0.0% | 0.0% | 0.0% | 0.0% |
| slow_decomposed | 28 | 0.0% | 7.1% | 0.0% | 0.0% | 0.0% | 0.0% |
| mixed | 32 | 2.5% | 16.2% | 0.0% | 0.0% | 0.0% | 3.1% |
| benign | 47 | FBR 7.2% | FBR 3.2% | FBR 0.8% | FBR 0.8% | FBR 1.4% | FBR 0.7% |

## Unseen attack strategy: defenses trained without any slow attack

Detectors, thresholds and the MDP are fitted on 1864 training updates with every slow-split, slow-decomposed and mixed-slow sequence removed (as if only one-shot poisons such as MCPTox were known). The test set is unchanged.

| policy | ASR | FBR | review burden | detection delay | stopped before payload | cost/update |
|---|---|---|---|---|---|---|
| No protection | 100.0% | 0.0% | 0.0% | n/a | 0.0% | 23.06 |
| Hash pinning | 2.0% [0.0%, 4.8%] | 6.5% [2.1%, 8.4%] | 100.0% [100.0%, 100.0%] | 0.04 | 62.0% | 3.12 [2.22, 3.94] |
| Classifier (new text only) | 40.8% [31.3%, 50.0%] | 2.7% [0.5%, 5.0%] | 8.8% [6.1%, 12.0%] | 0.70 | 13.5% | 10.33 [7.99, 12.38] |
| Change-pair + threshold | 30.3% [22.0%, 39.2%] | 0.0% [0.0%, 0.0%] | 4.1% [2.4%, 6.1%] | 0.56 | 19.8% | 7.46 [5.40, 9.49] |
| Change-pair + history rule | 30.3% [22.0%, 39.2%] | 0.0% [0.0%, 0.0%] | 4.1% [2.4%, 6.1%] | 0.56 | 19.8% | 7.46 [5.40, 9.49] |
| Change-pair + cumulative threshold (ours) | 21.4% [14.3%, 29.3%] | 0.0% [0.0%, 0.0%] | 7.5% [5.1%, 10.0%] | 0.74 | 27.3% | 5.45 [3.70, 7.33] |
| Change-pair + MDP (ours) | 28.9% [20.8%, 37.7%] | 0.0% [0.0%, 0.0%] | 6.0% [4.0%, 8.4%] | 0.65 | 19.4% | 7.13 [5.19, 9.08] |

Tuned on the policy-fit set: threshold=[0.1, 0.5], new-only threshold=[0.05, 0.75], history rule theta=0.6, MDP risk bins=[0.1, 0.5]. Value iteration converged in 71 iterations.

Paired bootstrap, MDP minus baseline (95% CI; share of resamples where the MDP is lower):

| baseline | ASR diff | FBR diff | review diff | cost diff | P(MDP cost lower) |
|---|---|---|---|---|---|
| Change-pair + threshold | [-0.047, +0.011] | [+0.000, +0.000] | [+0.005, +0.035] | [-1.121, +0.302] | 0.784 |
| Change-pair + history rule | [-0.046, +0.011] | [+0.000, +0.000] | [+0.005, +0.034] | [-1.119, +0.318] | 0.77 |
| Change-pair + cumulative threshold (ours) | [+0.030, +0.124] | [+0.000, +0.000] | [-0.032, +0.001] | [+0.566, +2.874] | 0.001 |
| Classifier (new text only) | [-0.217, -0.030] | [-0.050, -0.005] | [-0.066, +0.007] | [-5.498, -1.050] | 0.999 |

Attack success rate by sequence type (benign row shows false-block rate):

| type | n | Hash pinning | Classifier (new text only) | Change-pair + threshold | Change-pair + history rule | Change-pair + cumulative threshold (ours) | Change-pair + MDP (ours) |
|---|---|---|---|---|---|---|---|
| one_shot | 22 | 6.4% | 9.1% | 0.0% | 0.0% | 0.0% | 0.0% |
| slow_split | 19 | 1.1% | 6.3% | 0.0% | 0.0% | 0.0% | 0.0% |
| slow_decomposed | 28 | 0.0% | 71.4% | 75.7% | 75.7% | 47.9% | 68.6% |
| mixed | 32 | 2.5% | 53.8% | 28.1% | 28.1% | 25.6% | 28.7% |
| benign | 47 | FBR 7.2% | FBR 3.0% | FBR 0.0% | FBR 0.0% | FBR 0.0% | FBR 0.0% |

### Sequence-level detection when slow attacks are unseen (ROC-AUC)

| attack type | attack seqs | max per-step risk | final cumulative risk | new text only |
|---|---|---|---|---|
| all | 101 | 0.9836 | 0.9842 | 0.8261 |
| one_shot | 22 | 1.0 | 1.0 | 0.9536 |
| slow_split | 19 | 1.0 | 1.0 | 0.9765 |
| slow_decomposed | 28 | 0.9696 | 0.9688 | 0.7082 |
| mixed | 32 | 0.9747 | 0.9774 | 0.7523 |

## Unseen slow strategy, with defender-side augmentation

Same setting, plus 390 synthetic slow-history updates that the defender makes by splitting its own known one-shot poisons into 2-4 pieces (benchmark/augment.py). No attacker slow template is used. The test set is unchanged.

| policy | ASR | FBR | review burden | detection delay | stopped before payload | cost/update |
|---|---|---|---|---|---|---|
| No protection | 100.0% | 0.0% | 0.0% | n/a | 0.0% | 23.06 |
| Hash pinning | 2.0% [0.0%, 4.8%] | 6.5% [2.1%, 8.4%] | 100.0% [100.0%, 100.0%] | 0.04 | 62.0% | 3.12 [2.22, 3.94] |
| Classifier (new text only) | 34.6% [24.5%, 43.0%] | 1.7% [0.0%, 4.1%] | 19.3% [14.5%, 24.3%] | 0.43 | 26.7% | 9.48 [6.99, 11.66] |
| Change-pair + threshold | 6.9% [2.0%, 11.7%] | 0.0% [0.0%, 0.0%] | 5.6% [3.7%, 7.9%] | 0.85 | 35.2% | 1.90 [0.63, 2.95] |
| Change-pair + history rule | 6.9% [2.0%, 11.7%] | 0.0% [0.0%, 0.0%] | 5.6% [3.7%, 7.9%] | 0.85 | 35.2% | 1.90 [0.63, 2.95] |
| Change-pair + cumulative threshold (ours) | 6.3% [2.0%, 11.6%] | 0.0% [0.0%, 0.0%] | 5.1% [3.2%, 7.4%] | 0.86 | 35.2% | 1.74 [0.62, 2.98] |
| Change-pair + MDP (ours) | 2.4% [0.0%, 5.1%] | 0.0% [0.0%, 0.0%] | 6.3% [4.2%, 8.6%] | 0.98 | 35.2% | 0.73 [0.10, 1.40] |

Tuned on the policy-fit set: threshold=[0.25, 0.7], new-only threshold=[0.05, 0.95], history rule theta=0.85, MDP risk bins=[0.1, 0.7]. Value iteration converged in 51 iterations.

Paired bootstrap, MDP minus baseline (95% CI; share of resamples where the MDP is lower):

| baseline | ASR diff | FBR diff | review diff | cost diff | P(MDP cost lower) |
|---|---|---|---|---|---|
| Change-pair + threshold | [-0.096, +0.000] | [+0.000, +0.000] | [-0.011, +0.023] | [-2.404, -0.012] | 0.98 |
| Change-pair + history rule | [-0.096, +0.000] | [+0.000, +0.000] | [-0.011, +0.023] | [-2.404, -0.012] | 0.98 |
| Change-pair + cumulative threshold (ours) | [-0.097, +0.000] | [+0.000, +0.000] | [-0.006, +0.031] | [-2.407, +0.003] | 0.972 |
| Classifier (new text only) | [-0.413, -0.226] | [-0.041, +0.000] | [-0.187, -0.076] | [-10.938, -6.390] | 1.0 |

Attack success rate by sequence type (benign row shows false-block rate):

| type | n | Hash pinning | Classifier (new text only) | Change-pair + threshold | Change-pair + history rule | Change-pair + cumulative threshold (ours) | Change-pair + MDP (ours) |
|---|---|---|---|---|---|---|---|
| one_shot | 22 | 6.4% | 14.5% | 0.0% | 0.0% | 0.0% | 0.0% |
| slow_split | 19 | 1.1% | 5.3% | 0.0% | 0.0% | 0.0% | 0.0% |
| slow_decomposed | 28 | 0.0% | 47.9% | 8.6% | 8.6% | 8.6% | 5.7% |
| mixed | 32 | 2.5% | 50.6% | 12.5% | 12.5% | 12.5% | 0.0% |
| benign | 47 | FBR 7.2% | FBR 2.3% | FBR 0.0% | FBR 0.0% | FBR 0.0% | FBR 0.0% |

## Robustness over 5 server splits: all strategies seen in training

Mean ± std across independent server-grouped splits (seeds [42, 1, 2, 3, 4]); last column counts splits where the policy had the lowest cost.

| policy | ASR | slow-decomposed ASR | FBR | review burden | cost/update | lowest-cost splits |
|---|---|---|---|---|---|---|
| No protection | 100.0% ± 0.0% | n/a | 0.0% ± 0.0% | 0.0% ± 0.0% | 22.62 ± 0.74 | 0 |
| Hash pinning | 2.0% ± 0.2% | 0.0% ± 0.0% | 6.7% ± 0.2% | 100.0% ± 0.0% | 3.15 ± 0.07 | 0 |
| Classifier (new text only) | 8.2% ± 1.3% | 8.1% ± 1.0% | 11.6% ± 4.1% | 39.4% ± 12.5% | 4.31 ± 0.42 | 0 |
| Change-pair + threshold | 0.0% ± 0.0% | 0.0% ± 0.0% | 1.2% ± 0.4% | 12.1% ± 4.3% | 0.32 ± 0.11 | 3 |
| Change-pair + history rule | 0.0% ± 0.0% | 0.0% ± 0.0% | 1.2% ± 0.4% | 12.1% ± 4.3% | 0.32 ± 0.11 | 0 |
| Change-pair + cumulative threshold (ours) | 0.2% ± 0.4% | 0.0% ± 0.0% | 1.5% ± 0.3% | 6.1% ± 3.4% | 0.28 ± 0.05 | 2 |
| Change-pair + MDP (ours) | 0.6% ± 0.5% | 0.0% ± 0.0% | 1.2% ± 0.3% | 8.9% ± 3.4% | 0.46 ± 0.11 | 0 |

## Robustness over 5 server splits: slow strategies unseen

Mean ± std across independent server-grouped splits (seeds [42, 1, 2, 3, 4]); last column counts splits where the policy had the lowest cost.

| policy | ASR | slow-decomposed ASR | FBR | review burden | cost/update | lowest-cost splits |
|---|---|---|---|---|---|---|
| No protection | 100.0% ± 0.0% | n/a | 0.0% ± 0.0% | 0.0% ± 0.0% | 22.62 ± 0.74 | 0 |
| Hash pinning | 2.0% ± 0.2% | 0.0% ± 0.0% | 6.7% ± 0.2% | 100.0% ± 0.0% | 3.15 ± 0.07 | 5 |
| Classifier (new text only) | 37.7% ± 2.9% | 68.8% ± 3.0% | 2.6% ± 0.9% | 10.3% ± 1.7% | 9.49 ± 0.91 | 0 |
| Change-pair + threshold | 30.5% ± 1.5% | 74.0% ± 3.3% | 0.0% ± 0.0% | 5.0% ± 0.6% | 7.44 ± 0.18 | 0 |
| Change-pair + history rule | 30.5% ± 1.5% | 74.0% ± 3.3% | 0.0% ± 0.0% | 5.0% ± 0.6% | 7.44 ± 0.18 | 0 |
| Change-pair + cumulative threshold (ours) | 22.0% ± 1.5% | 46.6% ± 1.8% | 0.0% ± 0.0% | 6.4% ± 1.6% | 5.52 ± 0.27 | 0 |
| Change-pair + MDP (ours) | 29.5% ± 1.1% | 68.4% ± 3.5% | 0.0% ± 0.0% | 5.9% ± 0.6% | 7.23 ± 0.23 | 0 |

## Robustness over 5 server splits: slow strategies unseen, defender-side augmentation

Mean ± std across independent server-grouped splits (seeds [42, 1, 2, 3, 4]); last column counts splits where the policy had the lowest cost.

| policy | ASR | slow-decomposed ASR | FBR | review burden | cost/update | lowest-cost splits |
|---|---|---|---|---|---|---|
| No protection | 100.0% ± 0.0% | n/a | 0.0% ± 0.0% | 0.0% ± 0.0% | 22.62 ± 0.74 | 0 |
| Hash pinning | 2.0% ± 0.2% | 0.0% ± 0.0% | 6.7% ± 0.2% | 100.0% ± 0.0% | 3.15 ± 0.07 | 0 |
| Classifier (new text only) | 32.3% ± 3.0% | 51.2% ± 4.0% | 2.8% ± 0.5% | 15.4% ± 1.0% | 8.82 ± 0.82 | 0 |
| Change-pair + threshold | 5.9% ± 5.5% | 10.9% ± 12.8% | 0.1% ± 0.2% | 3.9% ± 1.4% | 1.60 ± 1.39 | 3 |
| Change-pair + history rule | 5.9% ± 5.5% | 10.9% ± 12.8% | 0.1% ± 0.2% | 3.9% ± 1.4% | 1.60 ± 1.39 | 0 |
| Change-pair + cumulative threshold (ours) | 10.4% ± 4.8% | 20.8% ± 11.9% | 0.0% ± 0.1% | 3.3% ± 1.7% | 2.71 ± 1.19 | 0 |
| Change-pair + MDP (ours) | 5.1% ± 5.1% | 10.5% ± 12.3% | 0.1% ± 0.2% | 8.3% ± 1.6% | 1.45 ± 1.23 | 2 |

## Sensitivity (cost per update, lower is better)

| c_miss | reviewer error | threshold | history rule | cumulative threshold | MDP | MDP ASR | MDP review burden |
|---|---|---|---|---|---|---|---|
| 20 | 0.0 | 0.1114 | 0.1114 | 0.1449 | 0.217 | 1.0% | 6.5% |
| 20 | 0.05 | 0.1114 | 0.1114 | 0.1449 | 0.1407 | 0.2% | 4.7% |
| 20 | 0.1 | 0.1114 | 0.1114 | 0.1449 | 0.1757 | 0.8% | 4.7% |
| 20 | 0.2 | 0.1114 | 0.1114 | 0.1449 | 0.0979 | 1.0% | 0.6% |
| 50 | 0.0 | 0.1416 | 0.1416 | 0.2319 | 0.3415 | 1.0% | 7.9% |
| 50 | 0.05 | 0.195 | 0.2664 | 0.2319 | 0.1583 | 0.2% | 4.7% |
| 50 | 0.1 | 0.195 | 0.2679 | 0.2319 | 0.1231 | 0.2% | 2.9% |
| 50 | 0.2 | 0.195 | 0.195 | 0.2319 | 0.2637 | 1.2% | 2.6% |
| 100 | 0.0 | 0.3487 | 0.3487 | 0.3775 | 0.3475 | 0.0% | 15.7% |
| 100 | 0.05 | 0.3863 | 0.3863 | 0.2774 | 0.5979 | 1.2% | 6.6% |
| 100 | 0.1 | 0.3992 | 0.3992 | 0.2788 | 0.657 | 1.4% | 5.6% |
| 100 | 0.2 | 0.3803 | 0.3803 | 0.2916 | 0.6461 | 1.4% | 3.6% |
| 200 | 0.0 | 0.3487 | 0.3487 | 0.3775 | 0.3775 | 0.0% | 17.2% |
| 200 | 0.05 | 0.3863 | 0.3863 | 0.3901 | 0.946 | 1.0% | 9.3% |
| 200 | 0.1 | 0.3992 | 0.3992 | 0.3975 | 0.274 | 0.0% | 8.7% |
| 200 | 0.2 | 0.3239 | 0.3239 | 0.4061 | 0.237 | 0.0% | 5.9% |
| 500 | 0.0 | 0.4726 | 0.4726 | 0.4778 | 0.4512 | 0.0% | 20.9% |
| 500 | 0.05 | 0.4857 | 0.4857 | 0.5304 | 1.0925 | 0.4% | 14.5% |
| 500 | 0.1 | 0.3992 | 0.8228 | 0.5511 | 0.3309 | 0.0% | 9.8% |
| 500 | 0.2 | 0.3239 | 0.3239 | 0.5041 | 0.2888 | 0.0% | 1.4% |

Lowest-cost policy per setting: threshold 8/20, MDP 9/20, cumulative threshold 3/20.

## Learned MDP policy (visited states)

| step risk | cumulative risk | updates | prior max | visits | P(attack) | action |
|---|---|---|---|---|---|---|
| low | low | 1 | low | 545 | 0.004 | ALLOW |
| low | low | 3 | low | 348 | 0.001 | ALLOW |
| low | low | 2 | low | 317 | 0.001 | ALLOW |
| high | high | 3 | high | 276 | 0.983 | BLOCK |
| high | high | 1 | low | 267 | 0.9 | BLOCK |
| low | low | 3 | med | 169 | 0.008 | ALLOW |
| high | high | 2 | high | 128 | 0.987 | BLOCK |
| med | med | 1 | low | 84 | 0.262 | ALLOW |
| low | low | 3 | high | 79 | 0.004 | ALLOW |
| med | low | 1 | low | 62 | 0.068 | ALLOW |
| low | med | 1 | low | 47 | 0.027 | ALLOW |
| low | med | 3 | med | 47 | 0.006 | ALLOW |
| low | low | 2 | med | 45 | 0.007 | ALLOW |
| low | med | 3 | high | 38 | 0.059 | ALLOW |
| med | low | 3 | low | 34 | 0.209 | ALLOW |
| high | med | 3 | high | 33 | 0.921 | BLOCK |
| med | low | 2 | low | 30 | 0.139 | ALLOW |
| low | med | 2 | med | 27 | 0.011 | ALLOW |
| med | high | 2 | high | 27 | 0.904 | BLOCK |
| high | med | 2 | low | 26 | 0.567 | QUARANTINE |
| high | high | 2 | med | 26 | 0.752 | BLOCK |
| low | med | 2 | low | 24 | 0.012 | ALLOW |
| high | med | 1 | low | 24 | 0.332 | QUARANTINE |
| high | med | 3 | med | 23 | 0.763 | QUARANTINE |
| med | high | 1 | low | 20 | 0.348 | ALLOW |
| high | low | 3 | low | 20 | 0.443 | ALLOW |
| high | high | 3 | med | 20 | 0.776 | BLOCK |
| med | med | 2 | low | 19 | 0.215 | ALLOW |
| high | low | 2 | low | 19 | 0.415 | ALLOW |
| med | med | 2 | med | 18 | 0.121 | ALLOW |
| high | high | 2 | low | 17 | 0.739 | BLOCK |
| med | med | 3 | low | 16 | 0.253 | ALLOW |
| med | med | 3 | med | 16 | 0.253 | ALLOW |
| med | med | 3 | high | 16 | 0.488 | QUARANTINE |
| high | high | 3 | low | 14 | 0.887 | BLOCK |
| low | med | 2 | high | 13 | 0.022 | ALLOW |
| low | med | 3 | low | 13 | 0.022 | ALLOW |
| med | high | 3 | high | 13 | 0.736 | BLOCK |
| low | low | 2 | high | 12 | 0.023 | ALLOW |
| med | low | 3 | med | 12 | 0.023 | ALLOW |
| high | med | 3 | low | 11 | 0.359 | QUARANTINE |
| high | med | 2 | med | 9 | 0.73 | ALLOW |
| med | low | 3 | high | 8 | 0.589 | ALLOW |
| med | high | 2 | med | 8 | 0.811 | BLOCK |
| low | high | 3 | high | 7 | 0.038 | ALLOW |
| low | high | 2 | high | 5 | 0.051 | ALLOW |
| low | high | 3 | med | 5 | 0.051 | ALLOW |
| high | low | 3 | med | 5 | 0.217 | ALLOW |
| high | low | 3 | high | 5 | 0.384 | QUARANTINE |
| med | low | 2 | med | 4 | 0.261 | QUARANTINE |
| low | high | 3 | low | 3 | 0.076 | QUARANTINE |
| med | med | 2 | high | 1 | 0.652 | QUARANTINE |
| med | high | 2 | low | 1 | 0.152 | QUARANTINE |
| med | high | 3 | low | 1 | 0.152 | QUARANTINE |
| med | high | 3 | med | 1 | 0.152 | QUARANTINE |
| high | low | 1 | low | 1 | 0.652 | QUARANTINE |
| high | med | 2 | high | 1 | 0.652 | BLOCK |
