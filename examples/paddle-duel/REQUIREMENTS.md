# Paddle Duel — Product Requirements

## 1. Product vision

Build a browser implementation of a classic local two-player paddle-and-ball game.

Two paddles defend opposite sides of a playfield. A ball moves continuously,
bounces from walls and paddles, and awards a point when it crosses a goal line.

The project demonstrates simultaneous keyboard input, deterministic physics,
scoring and real-time browser validation without external services.

## 2. Goals

- Two local players.
- Simultaneous keyboard control.
- Deterministic collision rules.
- Score, serve, pause, restart and match victory.
- Responsive browser UI and automated E2E.

## 3. Non-goals

- online multiplayer
- accounts/leaderboards
- AI opponent
- cloud persistence
- touch controls
- required sound

## 4. Domain model

### Game states
`ready | serving | playing | paused | match_over`

### Paddle
Each paddle has a vertical position, dimensions and speed.
Paddles cannot leave the playfield.

### Ball
Ball has position, velocity and collision dimensions.

### Match
Default winning score: 5.

## 5. Functional requirements

| ID | Requirement | Priority | Acceptance |
|---|---|---:|---|
| FR-PDL-001 | Start | MUST | Space or visible Start begins a match. |
| FR-PDL-002 | Left controls | MUST | W/S move left paddle. |
| FR-PDL-003 | Right controls | MUST | Arrow Up/Down move right paddle. |
| FR-PDL-004 | Simultaneous input | MUST | Both paddles may move concurrently. |
| FR-PDL-005 | Bounds | MUST | Paddles remain inside the playfield. |
| FR-PDL-006 | Ball step | MUST | Ball advances deterministically from state and logical timestep. |
| FR-PDL-007 | Wall bounce | MUST | Top/bottom collision reverses vertical direction without scoring. |
| FR-PDL-008 | Paddle collision | MUST | Ball moving toward a paddle bounces on valid contact. |
| FR-PDL-009 | No phantom bounce | MUST | Ball moving away from a paddle cannot collide with it again. |
| FR-PDL-010 | Contact influence | MUST | Contact offset deterministically affects bounded outgoing vertical velocity. |
| FR-PDL-011 | Goals | MUST | Crossing a goal line awards exactly one point to the opponent. |
| FR-PDL-012 | Serve reset | MUST | After scoring, ball/paddles enter a documented serve state. |
| FR-PDL-013 | Score | MUST | Both scores remain visible. |
| FR-PDL-014 | Win | MUST | First player to winning score enters `match_over`. |
| FR-PDL-015 | Pause | MUST | P or visible control pauses without domain progression. |
| FR-PDL-016 | Restart | MUST | Restart resets scores, paddles, ball and state. |
| FR-PDL-017 | Determinism | MUST | Same state/input/step produces same next state. |

## 6. Serve and collision rules

A serve:
- starts from a valid central position
- has non-zero horizontal velocity
- has bounded vertical velocity
- is deterministic under a test seed/source

After paddle collision:
- horizontal direction reverses
- ball is resolved outside the paddle
- contact position may alter vertical velocity
- speed stays within configured bounds

A goal scores exactly once before serve reset.

## 7. Input rules

Keyboard input is state-based, not dependent on OS key-repeat frequency.

Both players can hold movement keys simultaneously.

Conflicting up/down input for one paddle must have a documented deterministic
result, such as no movement.

## 8. UI requirements

| ID | Requirement |
|---|---|
| FR-UI-001 | Playfield, paddles, ball, center line and score are clear. |
| FR-UI-002 | Both players' controls are visible. |
| FR-UI-003 | Pause and match-over states are clear. |
| FR-UI-004 | Visible Start/Restart and Pause/Resume controls exist. |
| FR-UI-005 | Winner announcement does not rely only on color. |
| FR-UI-006 | Keyboard focus is visible. |
| FR-UI-007 | Layout remains usable at 320 CSS px. |

## 9. Edge cases

Test:
- both players moving simultaneously
- conflicting keys for one player
- corner paddle contact
- high-speed approach to paddle
- repeated pause/resume
- repeated restart/start
- goal during resize
- focus loss/return
- final winning point

## 10. Non-functional requirements

| ID | Requirement |
|---|---|
| NFR-001 | One documented local start command after install. |
| NFR-002 | No external/paid service. |
| NFR-003 | Physics/game state is unit-testable independently of rendering. |
| NFR-004 | Logical collision geometry is independent of CSS scaling. |
| NFR-005 | No uncaught browser errors in supported gameplay. |
| NFR-006 | Avoid unnecessary backend infrastructure. |

## 11. Testing requirements

### Unit
Cover:
- paddle movement/clamping
- simultaneous input
- ball stepping
- wall bounces
- both paddle collisions
- moving-away non-collision
- contact-offset behavior
- both goal directions
- exactly-one-point scoring
- serve
- win
- pause no-op
- deterministic simulation

### Browser E2E
Verify:
1. start
2. both control schemes
3. simultaneous movement
4. deterministic paddle hit
5. score
6. pause
7. victory
8. restart
9. narrow viewport
10. no console/page errors

## 12. Adversarial focus

Try:
- holding all movement keys
- rapid pause/resume
- repeated Start/Restart
- paddle corner hits
- focus changes
- resize during a rally
- keyboard-only UI navigation
- long rally

## 13. Acceptance scenarios

### AS-001 — Rally
Given active play, when the ball reaches a paddle inside its bounds, then the
ball bounces back and score does not change.

### AS-002 — Score
Given the ball crosses the right goal, then left score increments exactly once
and a new serve begins.

### AS-003 — Simultaneous controls
Given W and Arrow Down are held, then both paddles move concurrently within bounds.

### AS-004 — Pause
Given active play, when paused across multiple logical steps, then ball, paddles
and scores remain unchanged.

### AS-005 — Victory
Given a player is one point below the winning score, when that player scores,
then match state becomes `match_over` and winner is visible.

## 14. Suggested phases

### Phase 1 — Game engine
Input state, paddle movement, ball physics, collisions, scoring, serve and unit tests.

### Phase 2 — Browser UI
Rendering, keyboard integration, state/score UI, pause/restart, responsiveness.

### Phase 3 — QA/release
Playwright, adversarial review, defect loop, final regressions.

## 15. Final success criteria

Complete when:
- all MUST requirements pass
- AS-001 through AS-005 pass
- unit/E2E suites pass
- simultaneous control is independently verified
- no blocking defect remains
- no adversarial finding remains pending
