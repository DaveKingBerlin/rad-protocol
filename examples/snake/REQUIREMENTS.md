# Snake — Product Requirements

## 1. Product vision

Build a small, polished browser implementation of classic Snake.

The player controls a continuously moving snake on a 20×20 grid, collects food,
grows, earns points, and loses after wall or self collision.

The example must be deterministic, keyboard accessible and require no external
service.

## 2. Goals

- Complete playable Snake game.
- Keyboard-first interaction.
- Deterministic grid-based rules.
- Score, pause, game over and restart.
- Unit and browser E2E validation.

## 3. Non-goals

- accounts or leaderboard
- online multiplayer
- cloud persistence
- sound requirement
- mobile touch controls
- backend service unless implementation has a justified reason

## 4. Domain model

### Board
- 20 columns × 20 rows.
- Coordinates are integer grid cells.

### Snake
- Ordered sequence of unique cells.
- First cell is the head.
- Direction: `up | down | left | right`.

### Food
- Exactly one food cell during active play.
- Food must never overlap the snake.

### Game state
`ready | playing | paused | game_over | completed`

`completed` is used if the snake fills the complete board.

## 5. Functional requirements

| ID | Requirement | Priority | Acceptance |
|---|---|---:|---|
| FR-SNK-001 | Start game | MUST | Space or visible Start begins a clean game. |
| FR-SNK-002 | Movement | MUST | Snake advances exactly one grid cell per logical tick. |
| FR-SNK-003 | Controls | MUST | Arrow keys and WASD change direction. |
| FR-SNK-004 | Reverse prevention | MUST | Immediate 180° reversal into segment two is rejected. |
| FR-SNK-005 | Food placement | MUST | Exactly one food exists and never overlaps the snake. |
| FR-SNK-006 | Food collection | MUST | Entering food grows the snake by one and increments score. |
| FR-SNK-007 | Collision | MUST | Wall or body collision ends play. |
| FR-SNK-008 | Score | MUST | Current/final score is visible. |
| FR-SNK-009 | Pause | MUST | P or visible control pauses/resumes without state mutation. |
| FR-SNK-010 | Restart | MUST | Restart creates a clean game without page reload. |
| FR-SNK-011 | Determinism | MUST | Same state + input + tick produces same next state. |
| FR-SNK-012 | Full board | MUST | Filling all cells ends as `completed`, not an infinite food-placement loop. |

## 6. Input rules

- Up / W → up
- Down / S → down
- Left / A → left
- Right / D → right
- P → pause/resume
- Space → start/restart when not playing

Rapid direction input between ticks must remain deterministic and may not allow an
otherwise illegal reverse sequence.

## 7. UI requirements

| ID | Requirement |
|---|---|
| FR-UI-001 | Board, snake and food are visually distinguishable. |
| FR-UI-002 | Score and current game state are visible. |
| FR-UI-003 | Start/Restart and Pause/Resume have visible controls. |
| FR-UI-004 | Keyboard focus is visible. |
| FR-UI-005 | No required action needs a mouse. |
| FR-UI-006 | Layout works at 320 CSS px without horizontal page scrolling. |

The visual design should look like a game, not a generic admin dashboard.

## 8. Timing

Default logical tick: approximately 120 ms.

The implementation may choose another playable value, but:
- domain movement remains grid based
- pause stops logical ticks
- rendering delays must not create uncontrolled extra state transitions

## 9. Edge cases

Must cover:

- rapid Up/Left/Down sequences
- repeated pause clicks
- restart immediately after collision
- focus loss and return
- food generation with only one free cell
- complete-board state
- multiple key events between two ticks

## 10. Non-functional requirements

| ID | Requirement |
|---|---|
| NFR-001 | One documented local start command after dependency installation. |
| NFR-002 | No external/paid service. |
| NFR-003 | Domain logic is independently unit-testable from rendering. |
| NFR-004 | No uncaught browser errors during supported play. |
| NFR-005 | Default tests are deterministic. |
| NFR-006 | Keep architecture small; avoid unnecessary infrastructure. |

## 11. Testing requirements

### Unit tests
Must cover:
- movement in all directions
- reverse prevention
- food collection/growth
- valid food placement
- wall collision
- self collision
- pause no-op
- restart
- full-board completion
- rapid-input sequencing

### Browser E2E
Must verify:
1. start
2. keyboard direction change
3. deterministic food collection and score increase
4. pause stops movement
5. game-over behavior
6. restart
7. narrow viewport
8. zero console/page errors

QA may use a deterministic test fixture/state injection seam instead of waiting
for random food placement.

## 12. Adversarial focus

Try:
- key spam before a tick
- holding opposite keys
- repeated pause/resume
- repeated restart
- tab/focus changes
- 320 px viewport
- keyboard-only flow
- near-full-board state

## 13. Acceptance scenarios

### AS-001 — Basic movement
Given a ready game, when it starts and a valid direction is selected, then the
snake advances one cell per tick in that direction.

### AS-002 — Eat food
Given food in the next head cell, when one tick executes, then score increments,
snake length grows by one, and a new valid food position exists.

### AS-003 — Collision
Given the head moves beyond the board, when the tick executes, then state becomes
`game_over` and movement stops.

### AS-004 — Pause
Given an active game, when paused across several tick intervals, then snake,
food and score remain unchanged.

### AS-005 — Restart
Given game over, when restarted, then initial snake, score, direction and state
are restored without page reload.

## 14. Suggested phases

### Phase 1 — Deterministic engine
State, movement, food, collision, score, pause/restart and unit tests.

### Phase 2 — Browser game
Rendering, keyboard controls, visible controls, responsive layout.

### Phase 3 — QA/release
Playwright, adversarial review, defect loop, full regression.

## 15. Final success criteria

Complete when:
- all MUST requirements pass
- AS-001 through AS-005 pass
- unit and E2E suites pass
- QA independently validates gameplay
- adversarial review is resolved
- no blocking defect remains
