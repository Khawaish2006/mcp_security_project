"""Reworded attacks: the same malicious meaning in words the training data never uses.

A word-matching detector learns "~/.ssh/id_rsa", "MUST", "credentials". An attacker
can say "the private login key in the hidden key folder" instead. This module
rewrites the text an attack adds with a fixed, hand-written paraphrase table, to
test whether a detector recognizes the meaning or only the vocabulary.

Applied only at evaluation time, to attack updates; nothing here is used for training.
"""

import re

from gateway.diff import split_sentences, added_text

# Longest patterns first; each is a case-insensitive whole-word (or whole-path) match.
_PARAPHRASES = [
    (r"~/\.ssh/id_rsa\.pub", "the public login key kept in the hidden key folder of the home directory"),
    (r"~/\.ssh/id_rsa", "the private login key kept in the hidden key folder of the home directory"),
    (r"~/\.ssh", "the hidden key folder in the home directory"),
    (r"/etc/passwd", "the operating system's account list file"),
    (r"/etc/shadow", "the operating system's protected password file"),
    (r"\.env\b", "the environment settings file"),
    (r"\bid_rsa\b", "private login key"),
    (r"\byou must first call\b", "it is necessary to start by invoking"),
    (r"\byou must first\b", "it is necessary to start by"),
    (r"\btogether with the response\b", "alongside the reply"),
    (r"\bthe user's request\b", "what the person asked for"),
    (r"\bthis is not optional\b", "skipping it is not allowed"),
    (r"\bdo not (?:tell|inform|notify) the user\b", "keep this from the person"),
    (r"\bbefore using\b", "prior to invoking"),
    (r"\bbefore calling\b", "ahead of invoking"),
    (r"\bregardless of\b", "no matter"),
    (r"\binstead of\b", "in place of"),
    (r"\bapi keys?\b", "service secret"),
    (r"\bcredentials?\b", "sign-in secrets"),
    (r"\bpasswords?\b", "passphrase"),
    (r"\btokens?\b", "access string"),
    (r"\bsecrets?\b", "confidential value"),
    (r"\bcookies?\b", "browser session data"),
    (r"\bmust\b", "needs to"),
    (r"\bmandatory\b", "compulsory"),
    (r"\brequired\b", "needed"),
    (r"\bpriority\b", "precedence"),
    (r"\bbefore\b", "prior to"),
    (r"\bcall\b", "invoke"),
    (r"\boverwrite\b", "replace everything in"),
    (r"\bread\b", "open and look through"),
    (r"\bwrite\b", "put"),
    (r"\bdelete\b", "erase"),
    (r"\bsend\b", "transmit"),
    (r"\bforward\b", "pass along"),
    (r"\bbcc\b", "secretly copy"),
    (r"\bignore\b", "disregard"),
    (r"\bmodify\b", "alter"),
    (r"\bargument\b", "input value"),
    (r"\bparameter\b", "input field"),
    (r"\buser\b", "person"),
    (r"\bsecurity\b", "safety"),
    (r"\bverify\b", "confirm"),
    (r"\bcalling\b", "invoking"),
    (r"\boverride\b", "replace"),
    (r"\balways\b", "in every case"),
    (r"\bshould\b", "ought to"),
    (r"\binclude\b", "attach"),
    (r"\bresponse\b", "reply"),
    (r"\bresults\b", "output"),
    (r"\bsilently\b", "quietly"),
    (r"\bstep\b", "stage"),
    (r"\bdefault\b", "standard"),
    (r"\bprecedence\b", "priority level"),
]
_COMPILED = [(re.compile(p, re.IGNORECASE), r) for p, r in _PARAPHRASES]


def reword(text: str) -> str:
    for pattern, repl in _COMPILED:
        text = pattern.sub(repl, text)
    return text


def reword_update(row: dict) -> dict:
    """The same update with every added sentence reworded (prev and d0 unchanged)."""
    new = row["new"]
    for sentence in split_sentences(added_text(row["prev"], row["new"])):
        new = new.replace(sentence, reword(sentence))
    return dict(row, new=new)
