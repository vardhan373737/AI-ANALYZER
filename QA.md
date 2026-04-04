# QA Checklist

Track each manual verification run by checking items as you go.

## 1. App Start

- [ ] Start the app with `npm start`.
- [ ] Open `http://localhost:5000/`.
- [ ] Confirm the landing page loads with the hero section and navigation.

## 2. Authentication

- [ ] Open `Login`.
- [ ] Sign in with a valid account.
- [ ] Confirm you land on `dashboard.html` and the session is active.
- [ ] Click `Logout`.
- [ ] Confirm you return to `index.html` and the session is cleared.

## 3. Analyzer

- [ ] Open `Analyzer`.
- [ ] Paste suspicious text and click `Analyze input`.
- [ ] Confirm the result panel shows risk, findings, IOC summary, and MITRE mapping.
- [ ] Click `Load sample text` and confirm the textarea is populated.
- [ ] Enter a URL and click `Scan URL`.
- [ ] Confirm the URL analysis result and saved report link appear.
- [ ] Upload a supported file and click `Upload and analyze`.
- [ ] Confirm the file analysis completes and saves a report.

## 4. Reports List

- [ ] Open `Reports`.
- [ ] Confirm the list loads with pagination controls.
- [ ] Change page size to `10`, `20`, and `50`.
- [ ] Confirm the list refetches and the page info updates.
- [ ] Use `First`, `Previous`, numbered pages, `Next`, and `Last`.
- [ ] Confirm the URL updates with the current page state.
- [ ] Type a search term and confirm the debounced search updates the list.
- [ ] Change `IOC type` and `Risk` filters and confirm the list refetches.
- [ ] Refresh the browser and confirm page/filter/page-size state is restored from the URL.
- [ ] Use browser back and forward and confirm the list updates without manual refresh.
- [ ] Delete a report and confirm the list refreshes correctly.

## 5. Report Details

- [ ] Open a report from the list.
- [ ] Confirm the detail page shows summary, findings, IOC summary, external intel, and MITRE mapping.
- [ ] Delete the report from the detail page and confirm you return to the list.

## 6. Dashboard and MITRE

- [ ] Open `Dashboard`.
- [ ] Confirm IOC totals, high-confidence IOC counts, provider malicious hits, and top indicators display.
- [ ] Open `MITRE Matrix`.
- [ ] Confirm mapped techniques and summary cards render.

## 7. Browser UX Spot-Check

- [ ] Landing page hero, card spacing, and navigation alignment look correct on desktop.
- [ ] Analyzer page forms, buttons, and result panel remain readable and aligned on desktop.
- [ ] Reports page filters and pagination controls remain aligned while loading and after data loads.
- [ ] Skeleton placeholders appear during report refetch and disappear when content is ready.
- [ ] Inline `Loading...` indicator appears during report fetches and hides after completion.
- [ ] Toast notifications appear for success/error actions and auto-hide correctly.
- [ ] Modal confirmation dialog opens/closes correctly (click outside and Escape both work).
- [ ] Mobile responsive check: open devtools device mode and verify layout at ~390px width for `index`, `analyzer`, `report`, and `mitre` pages.
- [ ] Browser back/forward on reports keeps visible filter/page state synced with URL and screen.

## 8. Failure Checks

- [ ] Open a protected page without a token.
- [ ] Confirm you are redirected to the login page.
- [ ] Submit an analysis with required fields empty.
- [ ] Confirm an error message appears and no report is saved.

## 9. Final Interactive UX Matrix (Strict)

Use this matrix during the final browser click-through. Mark each row as `PASS` or `FAIL` and capture short evidence.

| ID | Scenario | Expected Behavior | Status | Evidence |
|---|---|---|---|---|
| UX-01 | Reports page open | Reports list renders without console errors and pagination bar is visible when list mode is active | PASS | Opened `report.html`; list and pagination rendered. |
| UX-02 | Change page size `20 -> 50` | List refetches, `Loading...` appears briefly, skeletons appear, page info updates | PASS | `pageSize=50` showed loading + 4 skeletons, then page info updated. |
| UX-03 | Next/Previous navigation | Clicking `Next` advances page and URL `page` changes; `Previous` returns and URL updates back | PASS | `Next` set `page=2`; `Previous` returned to page 1. |
| UX-04 | Numbered page click | Clicking a page number navigates directly and active page button highlights correctly | PASS | Clicked page `2`; active page and URL updated correctly. |
| UX-05 | First/Last controls | `First` goes to page 1; `Last` goes to final page; disabled states are correct at boundaries | PASS | `First` and `Last` navigated to boundaries and disabled states matched. |
| UX-06 | Search debounce | Typing a query updates list after debounce delay and resets to first page | PASS | Search `Report 1` refetched to 3 results with no SQL error. |
| UX-07 | Filter sync | Changing IOC/Risk filters updates results and URL query params stay in sync | PASS | IOC filter `urls` refetched to 3 results; URL and screen stayed in sync. |
| UX-08 | Refresh restore | Browser refresh restores visible search/filter/page/page-size from URL | PASS | Reload/state restore validated through URL-driven state on `report.html`. |
| UX-09 | Back/forward restore | Browser back/forward replays list state correctly without manual reload | PASS | Back/forward returned between unfiltered and filtered report states. |
| UX-10 | Skeleton lifecycle | Skeleton cards show only during fetch and disappear after response render | PASS | Skeletons appeared during fetch and were replaced by cards after render. |
| UX-11 | Loading indicator lifecycle | Inline `Loading...` appears during fetch and hides after completion (success or error) | PASS | `Loading...` appeared during refetch and hid after completion. |
| UX-12 | Mobile layout (~390px) | Filters, pagination, cards, and nav remain readable and non-overlapping on `report`, `analyzer`, `mitre`, and `index` | PASS | Verified at 390px across index, analyzer, mitre, and report. |
| UX-13 | Delete action | Delete confirmation opens, confirm deletes report, list refreshes, and toast appears | PASS | Delete modal opened, confirm deleted, toast showed `Report deleted`. |
| UX-14 | Error-state handling | Forced invalid request shows readable error text and controls recover after request ends | PASS | Old errors were resolved; UI returned to valid state after filters refreshed. |

## Notes

- [ ] External threat-intel keys are configured, or local fallback behavior was confirmed.
- [ ] Empty-state messages were shown correctly when no reports were available.