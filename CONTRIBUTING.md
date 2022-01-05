# Contents
* [Notes](#notes)
* [Contributing](#contributing)
* [Resolving Merge Conflicts](#resolving-merge-conflicts)
* [Best Practices for Contributing](#best-practices-for-contributing)
* [Attribution](#attribution)

# Notes

Any contributions received are assumed to be covered by the BSD 3-Clause license. We might ask you to sign a Contributor License Agreement before accepting a larger contribution. To learn more about ReproZip, see:
* [ReproZip Examples](https://examples.reprozip.org/)
* [ReproZip Documentation](https://docs.reprozip.org/)
* [ReproZip Demo Video](https://www.youtube.com/watch?v=-zLPuwCHXo0)

# Contributing

Please follow the [GitHub Community Guidelines](https://docs.github.com/en/github/site-policy/github-community-guidelines) in all your interactions with the project. If you would like to contribute to this project by modifying/adding to the code, please read the [Best Practices for Contributing](#best-practices-for-contributing) below and feel free to follow the standard GitHub workflow:

1. Fork the project.
2. Clone your fork to your computer.
 * From the command line: `git clone https://github.com/<USERNAME>/reprozip.git`
3. Change into your new project folder.
 * From the command line: `cd reprozip`
4. [optional]  Add the upstream repository to your list of remotes.
 * From the command line: `git remote add upstream https://github.com/ViDA-NYU/reprozip.git`
5. Create a branch for your new feature.
 * From the command line: `git checkout -b my-feature-branch-name`
6. Make your changes.
 * Avoid making changes to more files than necessary for your feature (i.e. refrain from combining your "real" pull request with incidental bug fixes). This will simplify the merging process and make your changes clearer.
7. Commit your changes. From the command line:
 * `git add <FILE-NAMES>`
 * `git commit -m "A descriptive commit message"`
8. While you were working some other changes might have gone in and break your stuff or vice versa. This can be a *merge conflict* but also conflicting behavior or code. Before you test, merge with master.
 * `git fetch upstream`
 * `git merge upstream/master`
9. Test. Run the program and do something related to your feature/fix.
10. Push the branch, uploading it to GitHub.
  * `git push origin my-feature-branch-name`
11. Make a "Pull Request" from your branch here on GitHub.

# Resolving Merge Conflicts

Depending on the order that Pull Requests get processed, your PR may result in a conflict and become un-mergable.  To correct this, do the following from the command line:

Switch to your branch: `git checkout my-feature-branch-name`
Pull in the latest upstream changes: `git pull upstream master`
Find out what files have a conflict: `git status`

Edit the conflicting file(s) and look for a block that looks like this:
```
<<<<<<< HEAD
my awesome change
=======
some other person's less awesome change
>>>>>>> some-branch
```

Replace all five (or more) lines with the correct version (yours, theirs, or
a combination of the two).  ONLY the correct content should remain (none of
that `<<<<< HEAD` stuff.)

Then re-commit and re-push the file.

```
git add the-changed-file.cs
git commit -m "Resolved conflict between this and PR #123"
git push origin my-feature-branch-name
```

The pull request should automatically update to reflect your changes.

## Best Practices for Contributing

* Before you start coding, open an issue so that the community can discuss your change to ensure it is in line with the goals of the project and not being worked on by someone else. This allows for discussion and fine tuning of your feature and results in a more succent and focused additions.
    * If you are fixing a small glitch or bug, you may make a PR without opening an issue.
    * If you are adding a large feature, create an issue so that we may give you feedback and agree on what makes the most sense for the project before making your change and submitting a PR (this will make sure you don't have to do major changes down the line).

* Pull Requests are eventually merged into the codebase. Please ensure they are:
    * Well tested by the author. It is the author's job to ensure their code works as expected.
    * Free of unnecessary log calls. Logging important for debugging, but when a PR is made, log calls should only be present when there is an actual error or to record some important piece of information or progress.

* If your code is untested, log heavy, or incomplete, prefix your PR with "[WIP]", so others know it is still being tested and shouldn't be considered for merging yet. This way we can still give you feedback or help finalize the feature even if it's not ready for prime time.

That's it! Following these guidelines will ensure that your additions are approved quickly and integrated into the project. Thanks for your contribution!

# Attribution

This CONTRIBUTING.md was adapted from [ProjectPorcupine's](https://github.com/TeamPorcupine/ProjectPorcupine)'s [CONTRIBUTING.md](https://github.com/TeamPorcupine/ProjectPorcupine/blob/master/CONTRIBUTING.md)

# Contact info

You are welcome to [subscribe to](https://groups.google.com/a/nyu.edu/g/reprozip) or contact our user mailing list [reprozip@nyu.edu](mailto:reprozip@nyu.edu) for questions, suggestions and discussions about using ReproZip.
