#!/usr/bin/env python3
from itertools import product

DRAFT, REVIEWED, PUBLISHED = range(3)
EVENTS = ("review", "publish", "edit", "noop")


def step(state, event):
    if event == "review" and state == DRAFT:
        return REVIEWED
    if event == "publish" and state == REVIEWED:
        return PUBLISHED
    if event == "edit" and state == DRAFT:
        return DRAFT
    if event == "noop":
        return state
    return None


reached_published = False
rejected_illegal = False
for events in product(EVENTS, repeat=4):
    state = DRAFT
    history = [state]
    legal = True
    for event in events:
        nxt = step(state, event)
        if nxt is None:
            rejected_illegal = True
            legal = False
            break
        state = nxt
        history.append(state)
    if not legal:
        continue
    if PUBLISHED in history:
        reached_published = True
        i = history.index(PUBLISHED)
        assert REVIEWED in history[:i], "clip publication skipped review"
        assert all(s == PUBLISHED for s in history[i:]), "published clip reopened"

assert reached_published, "published clip is unreachable"
assert rejected_illegal, "model never exercised an illegal publication transition"
print("clip publication transition-system model: ok")
