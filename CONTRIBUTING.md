# Contents
* [Notes](#notes)
* [Contributing](#contributing) 
* [Resolving Merge Conflicts](#resolving-merge-conflicts) 
* [Best Practices for Contributing](#best-practices-for-contributing) 
* [Attribution](#attribution)

# Notes
[Notes]: #notes

Any contributions received are assumed to be covered by the BSD 3-Clause license. We might ask you to sign a Contributor License Agreement before accepting a larger contribution. To learn more about ReproZip, see: 
* [ReproZip Examples](https://vida-nyu.github.io/reprozip-examples/)
* [ReproZip Documentation](https://reprozip.readthedocs.io/en/1.0.x/)
* [ReproZip Demo Video](https://www.youtube.com/watch?v=-zLPuwCHXo0)

# Contributing
[Contributing]: #contributing

Please note we use the [Citizen Code of Conduct](https://github.com/stumpsyn/policies/blob/master/citizen_code_of_conduct.md), please follow it in all your interactions with the project. If you would like to contribute to this project by modifying/adding to the program code, please read the [Best Practices for Contributing] below and feel free to follow the standard Github workflow:

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
8. While you were working some other pull request might have gone in the breaks your stuff or vice versa. This can be a *merge conflict* but also conflicting game logic or code. Before you test, merge with master.
 * `git fetch upstream`
 * `git merge upstream/master`
9. Test. Start the game and do something related to your feature/fix.
10. Push the branch, uploading it to Github.
  * `git push origin my-feature-branch-name`
11. Make a "Pull Request" from your branch here on GitHub.
  * Include screenshots demonstrating your change if applicable.

# Resolving Merge Conflicts
[Resolving Merge Conflicts]: #resolving-merge-conflicts

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
[Best Practices for Contributing]: #best-practices-for-contributing
* Before you start coding, open an issue so that the community can discuss your change to ensure it is in line with the goals of the project and not being worked on by someone else. This allows for discussion and fine tuning of your feature and results in a more succent and focused additions.
    * If you are fixing a small glitch or bug, you may make a PR without opening an issue.
    * If you are adding a large feature, create an issue prefixed with "[Discussion]" and be sure to take community feedback and get general approval before making your change and submitting a PR.

* Pull Requests represent final code. Please ensure they are:
     * Well tested by the author. It is the author's job to ensure their code works as expected.
     * Be free of unnecessary log calls. Logging is great for debugging, but when a PR is made, log calls should only be present when there is an actual error or to warn of an unimplemented feature.

* If your code is untested, log heavy, or incomplete, prefix your PR with "[WIP]", so others know it is still being tested and shouldn't be considered for merging yet.

* Small changes are preferable over large ones. The larger a change is the more likely it is to conflict with the project and thus be denied. If your addition is large, be sure to extensively discuss it in an "issue" before you submit a PR, or even start coding.

   * Document your changes in your PR. If you add a feature that you expect others to use, explain exactly how future code should interact with your additions.

   * Avoid making changes to more files than necessary for your feature (i.e. refrain from combining your "real" pull request with incidental bug fixes). This will simplify the merging process and make your changes clearer.

   * Include screenshots demonstrating your change if applicable. All UI changes should include screenshots.

That's it! Following these guidelines will ensure that your additions are approved quickly and integrated into the project. Thanks for your contribution!

# Attribution
[Attribution]: #attribution

This CONTRIBUTING.md was adapted from [ProjectPorcupine's](https://github.com/TeamPorcupine/ProjectPorcupine)'s [CONTRIBUTING.md](https://github.com/TeamPorcupine/ProjectPorcupine/blob/master/CONTRIBUTING.md)
