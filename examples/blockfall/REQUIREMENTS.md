# Blockfall — Product Requirements

## 1. Product vision

Build a browser-based falling-block puzzle game using the seven standard tetromino shapes.

Seven tetromino types fall into a 10×20 visible playfield. The player moves and
rotates pieces, clears horizontal lines, earns score, advances levels and loses
when a new piece cannot enter the board.

This example demonstrates a richer deterministic state machine than Snake or Paddle Duel.

## 2. Goals

- Seven tetrominoes.
- Deterministic 7-bag generation.
- Movement, rotation, soft/hard drop.
- Line clearing.
- Score and levels.
- Next-piece preview.
- Pause, game over and restart.
- Deterministic unit/E2E validation.

## 3. Non-goals

- official competitive certification
- multiplayer
- accounts/leaderboards
- hold piece
- ghost piece
- sound requirement
- cloud persistence

## 4. Domain model

Visible board: 10 columns × 20 rows.

Top-level states:
`ready | playing | paused | game_over`

Active domain state includes:
- locked board cells
- active piece
- next piece
- score
- cleared lines
- level
- logical fall timing

Required pieces:
`I O T S Z J L`

Each piece always contains exactly four blocks.

## 5. 7-bag generator

1. Start with all seven piece types exactly once.
2. Shuffle using an injectable deterministic random source.
3. Draw until empty.
4. Create a new bag.

Tests must be able to use a fixed seed or fixed sequence.

## 6. Functional requirements

| ID | Requirement | Priority | Acceptance |
|---|---|---:|---|
| FR-BLK-001 | Start | MUST | Space or visible Start creates a clean game. |
| FR-BLK-002 | Seven pieces | MUST | All seven types exist and contain exactly four blocks. |
| FR-BLK-003 | 7-bag | MUST | Each complete bag contains each type exactly once. |
| FR-BLK-004 | Automatic fall | MUST | Active piece descends according to controlled logical timing. |
| FR-BLK-005 | Horizontal movement | MUST | Left/Right move one valid cell. |
| FR-BLK-006 | Soft drop | MUST | Down accelerates controlled descent. |
| FR-BLK-007 | Hard drop | MUST | Space while playing moves to lowest valid position and locks. |
| FR-BLK-008 | CW rotation | MUST | Up or X attempts clockwise rotation. |
| FR-BLK-009 | CCW rotation | MUST | Z attempts counter-clockwise rotation. |
| FR-BLK-010 | Invalid actions | MUST | Invalid movement/rotation leaves state unchanged unless a defined kick resolves rotation. |
| FR-BLK-011 | Wall kicks | MUST | Rotations use a documented deterministic bounded kick table. |
| FR-BLK-012 | Lock | MUST | Piece locks only in a valid non-overlapping position. |
| FR-BLK-013 | Spawn/preview | MUST | After lock/line processing, preview becomes active and new preview is generated. |
| FR-BLK-014 | Clear lines | MUST | Completely filled rows clear atomically and rows above shift down. |
| FR-BLK-015 | Multi-line clear | MUST | 1–4 simultaneous rows clear in one resolution step. |
| FR-BLK-016 | Score | MUST | Score follows documented deterministic scoring. |
| FR-BLK-017 | Level | MUST | Level increases after configured cleared-line thresholds. |
| FR-BLK-018 | Speed | MUST | Fall interval decreases with level but has a safe minimum. |
| FR-BLK-019 | Next preview | MUST | Next piece is visible. |
| FR-BLK-020 | Pause | MUST | P pauses/resumes without logical falling. |
| FR-BLK-021 | Game over | MUST | Invalid spawn enters `game_over` without committing overlap. |
| FR-BLK-022 | Restart | MUST | Restart resets board, pieces, score, level, lines and timing. |
| FR-BLK-023 | Determinism | MUST | Equal state, sequence, inputs and timing steps produce equal state. |

## 7. Rotation system

Use a documented deterministic wall-kick system.

It may be simplified rather than an official guideline implementation, but:
- every piece rotates consistently
- O does not unexpectedly translate
- kicks are bounded
- collision checks are deterministic
- failed rotation leaves state unchanged
- wall/stack-adjacent rotations are tested

## 8. Lock behavior

Minimum:
- when downward movement is no longer possible, piece locks at the next defined lock step
- hard drop locks immediately
- no invalid overlapping locked state is possible

Advanced lock-delay reset behavior is out of scope unless explicitly documented.

## 9. Scoring

Default line-clear table:

| Lines | Base |
|---|---:|
| 1 | 100 |
| 2 | 300 |
| 3 | 500 |
| 4 | 800 |

Award: `base × (level + 1)`.

Drop points are optional but must be documented if implemented.

## 10. Level progression

Default:
- level starts at 0
- every 10 cleared lines increments level
- fall speed increases by deterministic formula
- interval is bounded by a minimum

Tests must control logical time rather than wait in real time.

## 11. Controls

| Action | Key |
|---|---|
| Left | Arrow Left |
| Right | Arrow Right |
| Soft drop | Arrow Down |
| Rotate CW | Arrow Up or X |
| Rotate CCW | Z |
| Hard drop | Space |
| Pause | P |

Start/Restart and Pause/Resume also have visible controls.

## 12. UI requirements

| ID | Requirement |
|---|---|
| FR-UI-001 | 10×20 playfield is clear. |
| FR-UI-002 | Piece types are visually distinguishable. |
| FR-UI-003 | Score, level and cleared lines are visible. |
| FR-UI-004 | Next preview is visible. |
| FR-UI-005 | Ready/paused/game-over are clear. |
| FR-UI-006 | Visible Start/Restart and Pause/Resume controls exist. |
| FR-UI-007 | Keyboard focus is visible. |
| FR-UI-008 | Layout works at 320 CSS px without page horizontal scrolling. |
| FR-UI-009 | Essential status does not rely only on color. |

## 13. Edge cases

Must test:
- every piece rotating at both walls
- rotation above locked cells
- I-piece in narrow spaces
- hard drop immediately after spawn
- repeated Hard Drop key events
- rapid Left/Right/Rotate
- pause exactly before fall step
- restart while paused
- 1/2/3/4 line clears
- top-row clear
- blocked spawn
- 7-bag boundary
- high level/minimum interval
- focus loss
- narrow viewport
- long deterministic simulation

## 14. Non-functional requirements

| ID | Requirement |
|---|---|
| NFR-001 | One documented local start command after install. |
| NFR-002 | No external/paid service. |
| NFR-003 | Domain logic independently testable from rendering. |
| NFR-004 | Time/randomness injectable or controllable in tests. |
| NFR-005 | No uncaught browser errors during supported play. |
| NFR-006 | Rapid input/line clearing remains responsive. |
| NFR-007 | Default automated tests are deterministic. |
| NFR-008 | Avoid unnecessary server/database infrastructure. |

## 15. Testing requirements

### Domain/unit
Must cover:
- piece definitions
- every rotation
- rotation round-trip
- valid/invalid movement
- wall kicks
- locked-cell collision
- automatic fall
- soft/hard drop
- lock
- single/double/triple/quad clear
- row collapse
- scoring
- level advancement
- minimum fall interval
- 7-bag membership/boundary
- deterministic sequence
- preview promotion
- blocked spawn/game over
- pause no-op
- clean restart
- rapid action sequencing

### Browser E2E
Must verify:
1. start
2. move
3. CW/CCW rotation
4. hard drop
5. deterministic line clear
6. score
7. level change under controlled setup
8. pause stops fall
9. next preview promotion
10. game over
11. restart
12. narrow viewport
13. no console/page errors

Do not wait for random piece sequences in E2E; use a deterministic test seam.

## 16. Adversarial focus

Try:
- input spam
- repeated hard drop
- input during lock/spawn transition
- pause around fall boundary
- resize during line resolution
- wall rotation for all pieces
- stack-adjacent rotations
- restart/game-over races
- focus changes
- bag exhaustion/boundary
- very high level via test setup
- long simulation

## 17. Acceptance scenarios

### AS-001 — Piece lifecycle
When a falling piece can no longer descend, it locks, lines resolve, preview
becomes active, and a new preview appears.

### AS-002 — Rotation
Given a T piece near a wall, a CW rotation either resolves through the documented
kick table or leaves state unchanged.

### AS-003 — Single line
A completed row clears atomically, upper rows shift down, lines increment and
score matches the table.

### AS-004 — Four-line clear
Four completed rows clear together and receive the documented four-line score.

### AS-005 — Pause
Across multiple fall intervals while paused, board, piece, score, lines and level
remain unchanged.

### AS-006 — Game over
If the next piece cannot spawn, state becomes `game_over` and no invalid overlap
is committed.

### AS-007 — Restart
Restart from active/paused/game-over produces a clean initial state.

### AS-008 — Seven-bag
For fourteen draws, draws 1–7 contain all seven types exactly once and draws
8–14 also contain all seven exactly once.

## 18. Suggested phases

### Phase 1 — Domain engine
Board, pieces, bag, movement, collision, rotation, falling, lock, lines, scoring.

### Phase 2 — Browser game
Rendering, keyboard input, timing integration, preview, score/status, pause/restart.

### Phase 3 — QA/hardening
Deterministic Playwright harness, timing/race tests, adversary, defect loop.

## 19. Final success criteria

Complete when:
- all MUST requirements pass
- AS-001 through AS-008 pass
- domain/frontend/E2E tests pass
- deterministic controlled simulation is proven
- QA independently validates core mechanics
- adversarial review is resolved
- no blocking defect remains
