# Changelog

All notable changes to the TechLearn Dashboard project will be documented in this file.

## [1.1.0] - 2025-07-15

### Added
- **Two-Way Sync:** Implemented a two-way synchronization between the "Courses in Progress" and "Study Schedule" sections.
- **Toggleable "Mark Complete" Button:** The "Mark Complete" button now toggles a course's completion status.
- **"Reset" Button:** Added a "Reset" button to each course card to reset progress to 0%.
- **"Next Course" Suggestions:** Added a suggestion feature to each course card, linking to a new `course-suggestion.html` page.
- **Dynamic Course Creation:** New study slots now automatically create a corresponding course card.
- **Two-Way Deletion:** Deleting a course from either the "Courses in Progress" or "Study Schedule" section removes it from both.
- **"Delete" Button:** Added a "Delete" button to each course card.

### Changed
- **Editable Course Names:** The course name in a new study slot is now editable by default.

### Fixed
- **Course/Schedule Mismatches:** Resolved inconsistencies between the "Courses in Progress" and "Study Schedule" sections.

## [1.0.0] - 2025-07-15

### Added
- Smart News Delivery section in dashboard with:
  - News cards with tags
  - Read time indicators
  - Read More buttons
  - Hover effects and animations
- News preferences in settings with predefined tech channels:
  - TechCrunch
  - Wired
  - The Verge
  - CNET
  - ZDNet
  - VentureBeat

### Changed
- Fixed AI Tools section text alignment
  - Added proper flex layout for card content
  - Consistent spacing between elements
  - Aligned "Learn More" buttons at bottom
- Improved study schedule container positioning
  - Moved below courses section
  - Added consistent spacing
  - Enhanced table styling

### Removed
- Save Settings button from settings page (now auto-saves)

### Fixed
- Text alignment issues in AI Tools cards
- Inconsistent container margins
- Study schedule spacing
- News preferences layout

### Style Updates
- Added consistent border radius (20px) across containers
- Implemented glassmorphism effect with `backdrop-filter`
- Standardized padding (30px) for all main containers
- Updated color scheme:
  - Background: rgba(30, 30, 60, 0.8)
  - Borders: rgba(99, 102, 241, 0.3)
  - Text: #e2e8f0 (headings), #94a3b8 (body)
- Added hover effects for interactive elements

### Technical Debt
- Need to implement auto-save functionality for settings
- Add error handling for news API failures
- Optimize images and lazy loading for news cards
- Add pagination for news feed

### Dependencies
- No new dependencies added
- All styling changes made to existing CSS files