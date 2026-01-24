# Contributing to Conch

Thank you for your interest in contributing to **Conch** - you came to the right place to learn
about how to make your contribution count. I start out by saying that I welcome all contributions,
from both novice and seasoned developers. If this is the first open-source project you've ever
contributed to, welcome! I am glad you are here.

Because I maintain this project in my free time only, I ask that you read this document to make
sure that you're not creating extra developer toil. I really do appreciate you taking the time to
improve **Conch**.

Please read this document carefully before contributing. Not following the guidelines here may
result in your contributions, such as issues or pull requests, being closed without further
discussion.

## Quick Reference

Just as a quick reminder, these are the places you should go to, depending on the scenario you're
trying to address.

| Task | Where to go |
|------|-------------|
| Report a bug | [Issues](https://github.com/dend/conch/issues) |
| Ask a question | [Discussions](https://github.com/dend/conch/discussions) |
| Request a feature | [Discussions](https://github.com/dend/conch/discussions) |

## AI-Assisted Contributions

This project has a fairly strict AI contribution policy, inspired by the awesome work of folks at
[`ghostty`](https://github.com/ghostty-org/ghostty/blob/main/AI_POLICY.md). I use AI tools myself
for a lot of the development and they have proven to be extremely valuable. Claude Code, at this
point, is my personal assistant in quite a bit of development.

That being said, I've also seen the sheer volume of drive-by slop that is being created in
projects that I maintain. This policy is in place to prevent that. It's **not an anti-AI stance**
but rather a firm position against **unqualified individuals using AI to burden me with
unnecessary work**. As a human maintaining this project, I want to spend my time on the most
impactful and interesting problems rather than triaging slop.

> [!WARNING]
> This policy is non-negotiable for any contributions, big or small.

The policy for this repo boils down to:

- **If you use AI for _any_ part of your contribution, you must disclose it.** Contributions made
  with AI are pretty easy to spot. Contributors **must** include the name of the tool and model
  they used and for what purpose (e.g., "_I used Claude Code with Opus 4.5 to fix the timeout bug
  in the OAuth request stack_"). Be prepared to explain your changes in a discussion.
- **Any contributions that change the code (i.e., a pull request) can only be accepted for issues
  that got maintainer approval.** Drive-by pull requests that were not previously vetted and
  **accepted to move forward** will be closed, with no exceptions. Always start with a discussion
  or an issue first.
- **Anything created by any AI model or tool (no matter how good) must be vetted by a
  contributor.** "Copilot says this should fix it" is not acceptable and will result in the
  contribution being closed and the submitter banned. Again, no exceptions.
- **Any issues that are created by AI with no human in the loop will be automatically closed.**
  Don't ask Claude to find problems with this code and then submit issues. Explain why do you
  think what you're encountering is a bug, how did you test it, and under what environment.
- **No AI-generated media of any kind allowed.** Text and code are OK as long as they follow the
  conditions above. Images and video will be automatically deleted and result in a ban.
- **Bad AI actors will be banned and ridiculed.** If you don't want your contribution to be used
  as an example of what _not to do_, make sure you follow the rules above.

## Issues

Issues are reserved for actionable work items. If you're unsure whether something is a bug or have
questions about the project, please start a
[Discussion](https://github.com/dend/conch/discussions) first.

> [!NOTE]
> Feature requests **must always** start with a
> [Discussion](https://github.com/dend/conch/discussions) first.

When opening an issue:

1. **Search existing issues to avoid duplicates.** Someone else may already have found the same
   issue and there might be an ongoing discussion.
2. **Provide a clear, descriptive title.** Make it easy to understand what exactly is the problem.
3. **Include steps to reproduce (for bugs).** Be as detailed as possible about _how_ I can
   reproduce the problem in my own environment.
4. **Include relevant environment details (.NET version, OS, etc.).** Windows behavior might be
   different than Linux. Using a DSL connection might be different than being on fiber. Include as
   much detail as possible so that I can reconstruct the conditions that you're operating under to
   verify if the issue is a bug or not.

## Pull Requests

Before opening a pull request, make sure that you read and agree to the
[AI-Assisted Contributions policy](#ai-assisted-contributions).

1. For non-trivial changes (e.g., architectural re-write), open a **Discussion** first to ensure
   the change aligns with project goals. For bugs, you must have an associated **Issue**.
2. Fork the repository.
3. Create a feature branch (`git checkout -b feature/your-feature`).
4. Make your changes.
5. Ensure the build passes:
   ```powershell
   .\scripts\build.ps1 -Clean
   ```
6. Commit your changes with a clear message.
7. Push to your branch and open a Pull Request.

Pull requests should:

- **Address a single concern.** Never bundle a bunch of unrelated changes under the same umbrella.
  If you're fixing a bug, fix that bug and don't modify any other files.
- **Include a clear description of the changes.** Not "Updates Conch".
- **Reference any related issues.** If a pull request is related to other efforts (or might impact
  other discussions), make sure to link them.

## Building

The project includes a build script with a TUI for easy building:

```powershell
# Clean build
.\scripts\build.ps1 -Clean

# Build and create NuGet package
.\scripts\build.ps1 -Clean -Pack

# Debug build
.\scripts\build.ps1 -Configuration Debug
```

All builds run with warnings as errors enabled. All contributions must pass a successful build.
