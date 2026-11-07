# Results

Runtime: 441.0 s. All numbers are on the held-out test split (servers never seen in training).

## Data

| split | updates | attack updates |
|---|---|---|
| train | 2009 | 690 |
| test | 411 | 233 |
| val | 413 | 181 |

## Detector (per update)

| model | precision | recall | F1 | FPR | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|
| Change-pair step head (ours) | 0.9141 | 0.7768 | 0.8399 | 0.0955 | 0.9455 | 0.9494 |
| New text only | 0.7984 | 0.867 | 0.8313 | 0.2865 | 0.8526 | 0.8554 |
| Cumulative head (ours, label: attack added since approval) | 0.8698 | 0.7167 | 0.7859 | 0.1404 | 0.8619 | 0.8945 |

### Recall / FPR by attack style

| style | n | change-pair recall | new-only recall |
|---|---|---|---|
| original | 68 | 0.8269 | 0.9615 |
| softened | 64 | 0.8333 | 0.8333 |
| templated | 142 | 0.7368 | 0.8421 |

### By change type

| change type | n | change-pair flagged | new-only flagged |
|---|---|---|---|
| bundle | 61 | 6.6% | 26.2% |
| default_value | 16 | 6.2% | 0.0% |
| error_note | 11 | 0.0% | 27.3% |
| example | 12 | 8.3% | 16.7% |
| malicious_one_shot | 43 | 88.4% | 95.3% |
| malicious_slow_decomposed | 133 | 73.7% | 84.2% |
| malicious_slow_split | 57 | 79.0% | 86.0% |
| optional_param | 11 | 9.1% | 18.2% |
| param_docs | 9 | 11.1% | 44.4% |
| process_note | 12 | 58.3% | 83.3% |
| rewording | 5 | 20.0% | 20.0% |
| security_note | 14 | 0.0% | 35.7% |
| tool_reference | 9 | 11.1% | 33.3% |
| version_note | 18 | 0.0% | 27.8% |

(For malicious types the share flagged is recall; for benign types it is the false-positive rate.)

Hard negatives (legitimate but suspicious-sounding official tools such as Fetch and get-env), scored out-of-fold: n=67 updates, FPR change-pair 10.4%, new-only 35.8%.

## Feature ablation (detector, per update)

| features | F1 | recall | FPR | ROC-AUC |
|---|---|---|---|---|
| full | 0.8399 | 0.7768 | 0.0955 | 0.9455 |
| no_embed_added | 0.7935 | 0.7339 | 0.1517 | 0.868 |
| no_embed_diff | 0.9099 | 0.9099 | 0.118 | 0.9591 |
| no_drift | 0.8318 | 0.7639 | 0.0955 | 0.9463 |
| no_scope | 0.8453 | 0.7854 | 0.0955 | 0.9454 |
| no_flags | 0.8445 | 0.7811 | 0.0899 | 0.9452 |
| flags_and_numeric_only | 0.63 | 0.5408 | 0.2303 | 0.7098 |

## Generalization

| held out | F1 | recall | FPR | ROC-AUC |
|---|---|---|---|---|
| paradigm Template-1 | 0.875 | 0.8448 | 0.0915 | 0.9539 |
| paradigm Template-2 | 0.8494 | 0.773 | 0.0995 | 0.919 |
| paradigm Template-3 | 0.8461 | 0.7535 | 0.0631 | 0.9428 |
| template phrasings | 0.8742 | 0.8373 | 0.1625 | 0.9027 |

## Sequence-level detection (ROC-AUC, attack histories vs benign histories)

| attack type | attack seqs | max per-step risk | final cumulative risk (d0 -> new) | new text only |
|---|---|---|---|---|
| all | 101 | 0.9444 | 0.9136 | 0.8921 |
| one_shot | 29 | 0.909 | 0.9545 | 0.9101 |
| slow_split | 15 | 0.9745 | 0.9021 | 0.9021 |
| slow_decomposed | 27 | 0.9716 | 0.9275 | 0.879 |
| mixed | 30 | 0.939 | 0.8674 | 0.8816 |

## Gateway policies (per sequence), all attack strategies seen in training

Costs: miss (completed attack)=100.0, false block=10.0, review=2.0, reviewer error=0.05. Averaged over reviewer-error seeds; brackets are bootstrap 95% CIs over test sequences.

| policy | ASR | FBR | review burden | detection delay | stopped before payload | cost/update |
|---|---|---|---|---|---|---|
| No protection | 100.0% | 0.0% | 0.0% | n/a | 0.0% | 24.57 |
| Hash pinning | 1.8% [0.0%, 5.3%] | 6.9% [2.1%, 8.9%] | 100.0% [100.0%, 100.0%] | 0.05 | 55.0% | 3.10 [2.22, 4.39] |
| Classifier (new text only) | 2.0% [0.0%, 4.9%] | 12.4% [7.4%, 19.1%] | 32.3% [25.2%, 39.3%] | 0.11 | 49.1% | 2.15 [1.17, 3.32] |
| Change-pair + threshold | 2.2% [0.0%, 5.8%] | 6.5% [2.9%, 10.4%] | 20.1% [15.7%, 24.6%] | 0.08 | 55.0% | 1.61 [0.68, 3.04] |
| Change-pair + history rule | 0.4% [0.0%, 2.0%] | 7.1% [3.5%, 11.2%] | 33.5% [25.3%, 40.0%] | 0.05 | 54.9% | 1.26 [0.85, 1.95] |
| Change-pair + cumulative threshold (ours) | 0.2% [0.0%, 1.9%] | 7.5% [3.5%, 12.2%] | 22.3% [16.5%, 28.3%] | 0.10 | 54.9% | 0.96 [0.64, 1.63] |
| Change-pair + MDP (ours) | 3.4% [0.0%, 7.4%] | 3.4% [1.2%, 7.4%] | 23.6% [18.8%, 28.4%] | 0.15 | 53.1% | 1.86 [0.80, 3.37] |

Tuned on the policy-fit set: threshold=[0.05, 0.9], new-only threshold=[0.05, 0.95], history rule theta=0.05, MDP risk bins=[0.05, 0.9]. Value iteration converged in 20 iterations.

Paired bootstrap, MDP minus baseline (95% CI; share of resamples where the MDP is lower):

| baseline | ASR diff | FBR diff | review diff | cost diff | P(MDP cost lower) |
|---|---|---|---|---|---|
| Change-pair + threshold | [-0.020, +0.052] | [-0.056, +0.005] | [+0.001, +0.069] | [-0.957, +1.693] | 0.348 |
| Change-pair + history rule | [+0.000, +0.070] | [-0.067, -0.006] | [-0.151, -0.037] | [-0.498, +2.177] | 0.174 |
| Change-pair + cumulative threshold (ours) | [+0.000, +0.071] | [-0.075, -0.002] | [-0.039, +0.068] | [-0.216, +2.374] | 0.064 |
| Classifier (new text only) | [-0.021, +0.061] | [-0.156, -0.037] | [-0.166, -0.009] | [-1.564, +1.471] | 0.566 |

Attack success rate by sequence type (benign row shows false-block rate):

| type | n | Hash pinning | Classifier (new text only) | Change-pair + threshold | Change-pair + history rule | Change-pair + cumulative threshold (ours) | Change-pair + MDP (ours) |
|---|---|---|---|---|---|---|---|
| one_shot | 29 | 6.2% | 3.5% | 3.5% | 0.0% | 0.0% | 0.0% |
| slow_split | 15 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 6.7% |
| slow_decomposed | 27 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| mixed | 30 | 2.0% | 0.0% | 3.3% | 0.7% | 0.7% | 7.3% |
| benign | 47 | FBR 7.0% | FBR 12.3% | FBR 5.3% | FBR 6.6% | FBR 6.8% | FBR 3.4% |

## Unseen attack strategy: defenses trained without any slow attack

Detectors, thresholds and the MDP are fitted on 1367 training updates with every slow-split, slow-decomposed and mixed-slow sequence removed (as if only one-shot poisons such as MCPTox were known). The test set is unchanged.

| policy | ASR | FBR | review burden | detection delay | stopped before payload | cost/update |
|---|---|---|---|---|---|---|
| No protection | 100.0% | 0.0% | 0.0% | n/a | 0.0% | 24.57 |
| Hash pinning | 1.8% [0.0%, 5.3%] | 6.9% [2.1%, 8.9%] | 100.0% [100.0%, 100.0%] | 0.05 | 55.0% | 3.10 [2.22, 4.39] |
| Classifier (new text only) | 14.6% [8.0%, 21.3%] | 0.7% [0.0%, 1.8%] | 12.4% [9.0%, 16.3%] | 0.59 | 27.3% | 4.34 [2.45, 6.02] |
| Change-pair + threshold | 29.3% [19.8%, 38.0%] | 0.0% [0.0%, 0.6%] | 6.7% [4.5%, 9.3%] | 0.47 | 10.9% | 7.72 [5.34, 9.60] |
| Change-pair + history rule | 29.3% [19.8%, 38.0%] | 0.0% [0.0%, 0.6%] | 6.7% [4.5%, 9.3%] | 0.47 | 10.9% | 7.72 [5.34, 9.60] |
| Change-pair + cumulative threshold (ours) | 27.3% [18.7%, 35.6%] | 0.0% [0.0%, 0.6%] | 4.3% [2.4%, 6.6%] | 0.59 | 11.7% | 7.10 [4.96, 9.17] |
| Change-pair + MDP (ours) | 27.9% [18.9%, 35.9%] | 0.0% [0.0%, 0.6%] | 5.6% [3.7%, 8.2%] | 0.50 | 11.3% | 7.31 [5.07, 9.33] |

Tuned on the policy-fit set: threshold=[0.05, 0.85], new-only threshold=[0.05, 0.45], history rule theta=1.01, MDP risk bins=[0.05, 0.5]. Value iteration converged in 32 iterations.

Paired bootstrap, MDP minus baseline (95% CI; share of resamples where the MDP is lower):

| baseline | ASR diff | FBR diff | review diff | cost diff | P(MDP cost lower) |
|---|---|---|---|---|---|
| Change-pair + threshold | [-0.051, +0.021] | [-0.006, +0.006] | [-0.028, +0.008] | [-1.208, +0.422] | 0.807 |
| Change-pair + history rule | [-0.051, +0.021] | [-0.006, +0.006] | [-0.028, +0.008] | [-1.208, +0.422] | 0.807 |
| Change-pair + cumulative threshold (ours) | [-0.067, +0.074] | [-0.005, +0.006] | [-0.008, +0.036] | [-1.555, +1.809] | 0.411 |
| Classifier (new text only) | [+0.049, +0.215] | [-0.018, +0.000] | [-0.110, -0.027] | [+0.979, +4.839] | 0.001 |

Attack success rate by sequence type (benign row shows false-block rate):

| type | n | Hash pinning | Classifier (new text only) | Change-pair + threshold | Change-pair + history rule | Change-pair + cumulative threshold (ours) | Change-pair + MDP (ours) |
|---|---|---|---|---|---|---|---|
| one_shot | 29 | 6.2% | 0.0% | 0.0% | 0.0% | 3.5% | 0.0% |
| slow_split | 15 | 0.0% | 0.0% | 0.0% | 0.0% | 6.7% | 0.0% |
| slow_decomposed | 27 | 0.0% | 41.5% | 81.5% | 81.5% | 66.7% | 74.1% |
| mixed | 30 | 2.0% | 10.7% | 21.3% | 21.3% | 23.3% | 24.0% |
| benign | 47 | FBR 7.0% | FBR 0.4% | FBR 0.0% | FBR 0.0% | FBR 0.0% | FBR 0.0% |

### Sequence-level detection when slow attacks are unseen (ROC-AUC)

| attack type | attack seqs | max per-step risk | final cumulative risk | new text only |
|---|---|---|---|---|
| all | 101 | 0.9343 | 0.9402 | 0.9232 |
| one_shot | 29 | 0.9985 | 0.9978 | 0.9927 |
| slow_split | 15 | 0.9972 | 0.9929 | 0.9915 |
| slow_decomposed | 27 | 0.7872 | 0.8329 | 0.7727 |
| mixed | 30 | 0.973 | 0.9546 | 0.9574 |

## Robustness over 5 server splits: all strategies seen in training

Mean ± std across independent server-grouped splits (seeds [42, 1, 2, 3, 4]); last column counts splits where the policy had the lowest cost.

| policy | ASR | slow-decomposed ASR | FBR | review burden | cost/update | lowest-cost splits |
|---|---|---|---|---|---|---|
| No protection | 100.0% ± 0.0% | n/a | 0.0% ± 0.0% | 0.0% ± 0.0% | 25.00 ± 0.66 | 0 |
| Hash pinning | 2.4% ± 0.8% | 0.0% ± 0.0% | 6.5% ± 0.9% | 100.0% ± 0.0% | 3.33 ± 0.30 | 0 |
| Classifier (new text only) | 1.8% ± 0.8% | 0.0% ± 0.0% | 10.0% ± 1.3% | 29.5% ± 4.6% | 1.86 ± 0.35 | 1 |
| Change-pair + threshold | 2.9% ± 0.9% | 0.0% ± 0.0% | 4.8% ± 1.4% | 20.7% ± 1.7% | 1.80 ± 0.35 | 0 |
| Change-pair + history rule | 0.9% ± 0.4% | 0.0% ± 0.0% | 5.1% ± 1.4% | 28.0% ± 2.8% | 1.21 ± 0.14 | 0 |
| Change-pair + cumulative threshold (ours) | 0.8% ± 0.6% | 0.0% ± 0.0% | 6.5% ± 0.8% | 19.9% ± 2.5% | 1.10 ± 0.23 | 2 |
| Change-pair + MDP (ours) | 1.6% ± 1.1% | 0.0% ± 0.0% | 4.8% ± 1.3% | 20.3% ± 2.9% | 1.27 ± 0.42 | 2 |

## Robustness over 5 server splits: slow strategies unseen

Mean ± std across independent server-grouped splits (seeds [42, 1, 2, 3, 4]); last column counts splits where the policy had the lowest cost.

| policy | ASR | slow-decomposed ASR | FBR | review burden | cost/update | lowest-cost splits |
|---|---|---|---|---|---|---|
| No protection | 100.0% ± 0.0% | n/a | 0.0% ± 0.0% | 0.0% ± 0.0% | 25.00 ± 0.66 | 0 |
| Hash pinning | 2.4% ± 0.8% | 0.0% ± 0.0% | 6.5% ± 0.9% | 100.0% ± 0.0% | 3.33 ± 0.30 | 4 |
| Classifier (new text only) | 16.5% ± 1.4% | 45.9% ± 3.3% | 0.9% ± 0.7% | 11.2% ± 1.6% | 4.89 ± 0.46 | 0 |
| Change-pair + threshold | 19.6% ± 5.1% | 54.3% ± 14.0% | 0.1% ± 0.1% | 9.4% ± 1.7% | 5.40 ± 1.24 | 0 |
| Change-pair + history rule | 19.4% ± 5.1% | 54.3% ± 14.0% | 0.1% ± 0.1% | 9.4% ± 1.8% | 5.37 ± 1.26 | 0 |
| Change-pair + cumulative threshold (ours) | 18.2% ± 5.9% | 50.2% ± 14.5% | 0.4% ± 0.4% | 10.0% ± 3.0% | 5.12 ± 1.32 | 1 |
| Change-pair + MDP (ours) | 20.3% ± 4.0% | 54.4% ± 10.4% | 0.1% ± 0.1% | 6.1% ± 0.7% | 5.48 ± 0.97 | 0 |

## Sensitivity (cost per update, lower is better)

| c_miss | reviewer error | threshold | history rule | cumulative threshold | MDP | MDP ASR | MDP review burden |
|---|---|---|---|---|---|---|---|
| 20 | 0.0 | 0.7697 | 0.6483 | 0.8954 | 1.0928 | 6.9% | 23.7% |
| 20 | 0.05 | 0.7863 | 0.7863 | 0.663 | 0.8546 | 5.3% | 13.5% |
| 20 | 0.1 | 0.8361 | 0.8361 | 0.7059 | 0.9569 | 7.9% | 10.2% |
| 20 | 0.2 | 0.8451 | 0.8451 | 0.7285 | 0.9431 | 10.7% | 4.1% |
| 50 | 0.0 | 1.2657 | 0.979 | 1.1155 | 1.2318 | 3.0% | 28.7% |
| 50 | 0.05 | 1.1831 | 0.997 | 0.9252 | 1.3075 | 3.2% | 23.0% |
| 50 | 0.1 | 1.2433 | 1.0831 | 0.9662 | 1.4971 | 4.5% | 18.9% |
| 50 | 0.2 | 1.6133 | 1.2038 | 1.086 | 1.4945 | 4.5% | 13.9% |
| 100 | 0.0 | 1.6154 | 1.2014 | 1.2014 | 0.7944 | 0.0% | 32.8% |
| 100 | 0.05 | 1.6121 | 1.2563 | 0.9638 | 1.8561 | 3.4% | 23.6% |
| 100 | 0.1 | 1.7585 | 1.0419 | 1.2731 | 2.4976 | 4.2% | 13.6% |
| 100 | 0.2 | 2.0722 | 1.2836 | 1.6147 | 2.2572 | 3.6% | 8.3% |
| 200 | 0.0 | 2.3147 | 1.2014 | 0.9734 | 0.841 | 0.0% | 35.0% |
| 200 | 0.05 | 2.429 | 1.4059 | 1.1036 | 1.2149 | 0.6% | 23.6% |
| 200 | 0.1 | 2.7175 | 1.757 | 1.4272 | 1.189 | 0.2% | 14.1% |
| 200 | 0.2 | 3.1507 | 1.6483 | 1.5388 | 4.513 | 4.0% | 3.3% |
| 500 | 0.0 | 4.4296 | 0.9963 | 0.9734 | 1.2029 | 0.0% | 52.9% |
| 500 | 0.05 | 5.0043 | 1.1377 | 1.3191 | 2.203 | 0.4% | 36.4% |
| 500 | 0.1 | 5.5945 | 2.6661 | 1.7378 | 4.307 | 1.4% | 9.8% |
| 500 | 0.2 | 6.3863 | 2.1283 | 2.014 | 2.6128 | 0.6% | 2.6% |

Lowest-cost policy per setting: history rule 5/20, cumulative threshold 12/20, MDP 3/20.

## Learned MDP policy (visited states)

| step risk | cumulative risk | updates | prior max | visits | P(attack) | action |
|---|---|---|---|---|---|---|
| low | low | 1 | low | 363 | 0.017 | ALLOW |
| low | low | 2 | low | 216 | 0.02 | ALLOW |
| low | low | 3 | low | 176 | 0.013 | ALLOW |
| high | high | 1 | low | 171 | 0.857 | BLOCK |
| high | high | 3 | high | 145 | 0.989 | BLOCK |
| low | low | 3 | med | 108 | 0.022 | ALLOW |
| med | med | 1 | low | 77 | 0.441 | QUARANTINE |
| high | high | 2 | high | 59 | 0.973 | BLOCK |
| med | low | 1 | low | 57 | 0.179 | QUARANTINE |
| med | high | 1 | low | 57 | 0.661 | QUARANTINE |
| low | low | 2 | med | 51 | 0.122 | ALLOW |
| low | med | 1 | low | 48 | 0.313 | QUARANTINE |
| high | med | 1 | low | 44 | 0.719 | BLOCK |
| low | med | 3 | med | 42 | 0.032 | ALLOW |
| high | med | 3 | high | 41 | 0.961 | BLOCK |
| med | low | 3 | low | 40 | 0.106 | QUARANTINE |
| low | med | 3 | low | 36 | 0.064 | ALLOW |
| low | low | 3 | high | 35 | 0.066 | QUARANTINE |
| low | med | 2 | low | 35 | 0.066 | ALLOW |
| med | low | 3 | med | 35 | 0.149 | ALLOW |
| high | high | 3 | med | 35 | 0.927 | BLOCK |
| med | low | 2 | low | 33 | 0.187 | ALLOW |
| med | high | 2 | high | 29 | 0.845 | BLOCK |
| low | med | 3 | high | 26 | 0.013 | ALLOW |
| high | med | 3 | med | 24 | 0.734 | BLOCK |
| low | med | 2 | med | 23 | 0.307 | ALLOW |
| med | med | 2 | low | 21 | 0.289 | ALLOW |
| med | high | 3 | high | 21 | 0.789 | BLOCK |
| med | med | 3 | high | 20 | 0.684 | BLOCK |
| high | high | 2 | low | 20 | 0.827 | BLOCK |
| high | high | 2 | med | 20 | 0.97 | BLOCK |
| med | med | 3 | med | 18 | 0.651 | QUARANTINE |
| low | high | 3 | med | 17 | 0.187 | QUARANTINE |
| high | med | 2 | low | 17 | 0.687 | QUARANTINE |
| low | high | 1 | low | 16 | 0.551 | QUARANTINE |
| med | high | 3 | med | 16 | 0.433 | QUARANTINE |
| low | high | 2 | high | 15 | 0.522 | QUARANTINE |
| med | med | 2 | med | 15 | 0.335 | QUARANTINE |
| med | med | 3 | low | 15 | 0.21 | QUARANTINE |
| low | low | 2 | high | 14 | 0.157 | ALLOW |
| low | high | 2 | med | 14 | 0.224 | ALLOW |
| low | high | 3 | high | 14 | 0.357 | QUARANTINE |
| med | high | 2 | med | 12 | 0.797 | BLOCK |
| high | low | 3 | low | 11 | 0.53 | ALLOW |
| low | med | 2 | high | 10 | 0.487 | QUARANTINE |
| high | low | 1 | low | 10 | 0.305 | QUARANTINE |
| high | low | 2 | low | 10 | 0.305 | ALLOW |
| high | low | 3 | med | 10 | 0.851 | BLOCK |
| high | med | 2 | med | 10 | 0.851 | BLOCK |
| high | med | 2 | high | 10 | 0.76 | BLOCK |
| med | low | 3 | high | 9 | 0.336 | ALLOW |
| high | med | 3 | low | 9 | 0.736 | BLOCK |
| med | high | 2 | low | 8 | 0.484 | QUARANTINE |
| low | high | 3 | low | 7 | 0.045 | ALLOW |
| high | low | 3 | high | 6 | 0.909 | BLOCK |
| med | med | 2 | high | 5 | 0.727 | QUARANTINE |
| high | low | 2 | med | 4 | 0.472 | QUARANTINE |
| high | high | 3 | low | 4 | 0.872 | BLOCK |
| low | high | 2 | low | 2 | 0.12 | QUARANTINE |
| med | low | 2 | med | 2 | 0.453 | QUARANTINE |
| med | low | 2 | high | 2 | 0.453 | QUARANTINE |
| med | high | 3 | low | 2 | 0.12 | QUARANTINE |
