# Manual QA Checklist

Use this checklist to verify the main user flows after changes.

## 1. App Start

1. Run `npm start`.
2. Open `http://localhost:5000/`.
3. Expected result: the landing page loads with the AI Cyber Analyzer hero section and navigation links.

## 2. Authentication Flow

1. Click `Login` in the top navigation.
2. Log in with a valid account.
3. Expected result: you land on `dashboard.html` and the session state shows as active.

4. Click `Logout`.
5. Expected result: you return to `index.html` and the session is cleared.

## 3. Analyzer Flow

1. Open `Analyzer` from the navigation.
2. Paste suspicious text into the input field.
3. Click `Analyze input`.
4. Expected result: the result panel shows a risk level, findings, IOC summary, and MITRE mapping.

5. Click `Load sample text`.
6. Expected result: the textarea fills with the sample phishing text.

7. Enter a URL and click `Scan URL`.
8. Expected result: the result panel updates with URL analysis and a saved report link.

9. Upload a `.txt`, `.log`, `.csv`, `.eml`, or `.pdf` file.
10. Click `Upload and analyze`.
11. Expected result: the file is analyzed, the output updates, and the report is saved.

## 4. Reports List

1. Open `Reports`.
2. Expected result: saved reports appear in a paginated list.

3. Change `Page size` to `10`, `20`, and `50`.
4. Expected result: the list refetches and the page indicator updates.

5. Click `First`, `Previous`, numbered pages, `Next`, and `Last`.
6. Expected result: the list updates correctly, controls disable at boundaries, and the URL query string reflects the current page.

7. Type a search term in `Search`.
8. Expected result: search triggers after a short delay and the list updates.

9. Toggle `IOC type` and `Risk` filters.
10. Expected result: the list refetches with the selected filters and the URL updates.

11. Refresh the browser.
12. Expected result: the same page, filters, and page size are restored from the URL.

13. Use the browser back and forward buttons after changing filters/pages.
14. Expected result: the list state updates without a manual refresh.

15. Delete a report.
16. Expected result: the report is removed, the list refreshes, and the pagination adjusts if needed.

## 5. Report Details

1. Open any report from the list.
2. Expected result: the detail view shows summary, findings, IOC summary, external intel, MITRE ATT&CK mapping, metadata, and created time.

3. Click `Delete this report`.
4. Expected result: the report is deleted and you return to the reports list.

## 6. Dashboard Checks

1. Open `Dashboard`.
2. Expected result: IOC totals, high-confidence IOC counts, top IOC category, provider malicious hits, and top indicators are visible.

3. Open `MITRE Matrix`.
4. Expected result: the matrix shows mapped techniques and summary cards.

## 7. Basic Failure Checks

1. Open a protected page without a token.
2. Expected result: you are redirected to the login page.

3. Leave required fields empty and submit an analysis.
4. Expected result: validation or error messaging appears and no report is saved.

## Notes

- If external threat-intel keys are not configured, provider enrichment should gracefully fall back to local IOC scoring.
- If no reports exist, empty-state messages should appear instead of broken UI.