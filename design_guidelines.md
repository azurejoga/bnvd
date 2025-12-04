# BNVD Vulnerability Tracker - Design Guidelines

## Design Approach
**Selected Approach**: Design System + Technical Tool Reference  
**Primary Inspiration**: Linear, GitHub Security Tab, Material Design  
**Rationale**: Utility-focused security tool requiring clear data presentation, efficient workflows, and professional aesthetics for cybersecurity professionals.

## Core Design Principles
1. **Information Clarity**: Prioritize readability of CVE data, severity levels, and technical details
2. **Scan-Friendly**: Enable quick assessment of vulnerability severity and status
3. **Professional Minimalism**: Clean, distraction-free interface focusing on data
4. **Action-Oriented**: Clear CTAs for sorting, filtering, and accessing AI insights

## Typography
- **Primary Font**: Inter or Roboto (web-safe, excellent readability)
- **Monospace Font**: JetBrains Mono or Fira Code (for CVE IDs, technical data)
- **Hierarchy**:
  - Page Titles: text-2xl font-semibold
  - Section Headers: text-lg font-medium
  - CVE IDs: text-base font-mono
  - Body Text: text-sm
  - Meta Information: text-xs text-gray-600

## Layout System
**Spacing Units**: Tailwind 2, 4, 6, 8, 12, 16 (p-2, m-4, gap-6, py-8, etc.)
- Page container: max-w-7xl mx-auto px-4
- Section spacing: py-12 or py-16
- Card padding: p-6
- Component gaps: gap-4 between related items, gap-8 between sections

## Component Library

### Navigation
- Fixed top navbar with logo, search bar, and navigation links
- Breadcrumb navigation for CVE detail pages
- Minimal, text-based navigation (avoid heavy graphics)

### Search & Filter Controls
- Prominent search bar in header
- Filter sidebar or horizontal filter bar with dropdowns for:
  - Vendor/Product
  - Severity (Critical/High/Medium/Low badges)
  - Date range (publication/lastModified)
  - Sort controls (newest first, oldest first, recently updated)
- Sort toggle buttons with active state indicators

### Data Display

**Vulnerability Cards/Table**
- List view (default): Table-style rows with columns for CVE-ID, Description snippet, Severity badge, Published date, Updated date
- Severity badges: Prominent, color-coded indicators (Critical=red, High=orange, Medium=yellow, Low=gray)
- Hover state: Subtle background change, cursor pointer
- Click: Navigate to detail page

**CVE Detail Page**
- Hero section: CVE-ID (large, monospace), severity badge, published/updated dates
- Information grid layout:
  - Left column (2/3 width): Description, CVSS scores, affected products (CPEs), CWEs, references
  - Right column (1/3 width): Metadata card (dates, source, links)
- Section dividers: Horizontal lines or subtle background changes
- **"Analisar com IA" Button**: Prominent, primary button that opens chat.openai.com with pre-filled vulnerability context in Portuguese. Position in top-right of hero section or as floating action

### Forms
- Clean input fields with subtle borders
- Labels above inputs
- Validation states (error borders, helper text)
- Primary action buttons (search, submit)

### Buttons
- Primary: Solid background, medium weight
- Secondary: Outlined or ghost style
- Severity badges: Small, rounded, uppercase text
- Icon buttons for actions (refresh, export, etc.)

### Data Tables
- Striped or hover rows for scannability
- Fixed header on scroll
- Sortable columns with arrow indicators
- Pagination controls at bottom
- Responsive: Stack columns on mobile

### GitHub Action Documentation Page
- Step-by-step installation guide
- Code snippets in bordered containers with copy button
- Visual examples/screenshots of Action in use
- Configuration options clearly listed

### CLI Documentation
- Command syntax in monospace blocks
- Example usage with outputs
- Parameter tables

## Interaction Patterns
- Instant sort/filter application (no page reload)
- Skeleton loaders for data fetching
- Toast notifications for actions (success/error messages)
- Modal overlays for confirmations if needed
- Smooth transitions (150ms-300ms) for state changes

## Responsive Behavior
- Desktop (lg+): Full layout with sidebars, multi-column data
- Tablet (md): 2-column layouts, collapsible filters
- Mobile: Single column, hamburger menu, stacked cards

## Accessibility
- Semantic HTML throughout
- ARIA labels for interactive elements
- Keyboard navigation support (tab order, enter to activate)
- Sufficient color contrast (WCAG AA minimum)
- Focus indicators on all interactive elements

## Images & Assets
**Icons**: Use Heroicons (outline style) for UI elements - search, filter, sort arrows, external links, chevrons
**Logo**: BNVD branding in header (text-based or simple graphic)
**No Hero Images**: This is a data-focused tool, no decorative hero sections
**Badges**: Generate severity badges programmatically (colored backgrounds with text)

## Special Notes
- **No animations** except micro-interactions (hover states, loading spinners)
- **Monochrome palette** with severity accent colors only
- **Data density**: Maximize information visible without scrolling where practical
- **Copy-friendly**: CVE IDs and technical data should be easily selectable/copyable
- **Link styling**: External links with subtle icon indicator