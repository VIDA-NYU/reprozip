# Contents
* [Notes](#notes)
* [Contributing](#contributing)  
* [Resolving Merge Conflicts](#resolving-merge-conflicts)  
* [Best Practices for Contributing](#best-practices-for-contributing)  
* [Code of Conduct](#code-of-conduct)
* [Attribution](#attribution)

# Notes
[Notes]: #notes

Any contributions received are assumed to be covered by the BSD 3-Clause license. We might ask you to sign a Contributor License Agreement before accepting a larger contribution. To learn more about ReproZip, see: 
* [ReproZip Examples](https://vida-nyu.github.io/reprozip-examples/)
* [ReproZip Documentation](https://reprozip.readthedocs.io/en/1.0.x/)
* [ReproZip Demo Video](https://www.youtube.com/watch?v=-zLPuwCHXo0)

# Contributing
[Contributing]: #contributing

Please note we have a code of conduct, please follow it in all your interactions with the project. If you would like to contribute to this project by modifying/adding to the program code, please read the [Best Practices for Contributing] below and feel free to follow the standard Github workflow:

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
 * Very much avoid making changes to the Unity-specific files, like the scene and the project settings unless absolutely necessary. Changes here are very likely to cause difficult to merge conflicts. Work in code as much as possible. (We will be trying to change the UI to be more code-driven in the future.) Making changes to prefabs should generally be safe -- but create a copy of the main scene and work there instead (then delete your copy of the scene before committing).
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

## Code of Conduct
[Code of Conduct]: #code-of-conduct

### Our Pledge

In the interest of fostering an open and welcoming environment, we as contributors and maintainers pledge to making participation in our project and our community a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

Examples of behavior that contributes to creating a positive environment include:

* Using welcoming and inclusive language
* Being respectful of differing viewpoints and experiences
* Gracefully accepting constructive criticism
* Focusing on what is best for the community
* Showing empathy towards other community members

Examples of unacceptable behavior by participants include:

* The use of sexualized language or imagery and unwelcome sexual attention or advances
* Trolling, insulting/derogatory comments, and personal or political attacks 
* Public or private harassment
* Publishing others' private information, such as a physical or electronic address, without explicit permission
* Other conduct which could reasonably be considered inappropriate in a professional setting

### Our Responsibilities

Project maintainers are responsible for clarifying the standards of acceptable behavior and are expected to take appropriate and fair corrective action in response to any instances of unacceptable behavior.

Project maintainers have the right and responsibility to remove, edit, or reject comments, commits, code, wiki edits, issues, and other contributions that are not aligned to this Code of Conduct, or to ban temporarily or permanently any contributor for other behaviors that they deem inappropriate, threatening, offensive, or harmful.

### Scope

This Code of Conduct applies both within project spaces and in public spaces when an individual is representing the project or its community. Examples of representing a project or community include using an official project e-mail address, posting via an official social media account, or acting as an appointed representative at an online or offline event. Representation of a project may be further defined and clarified by project maintainers.

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be reported by contacting the project team at [reprozip-dev@vgc.poly.edu](mailto:reprozip-dev@vgc.poly.edu). All complaints will be reviewed and investigated and will result in a response that is deemed necessary and appropriate to the circumstances. The project team is obligated to maintain confidentiality with regard to the reporter of an incident. Further details of specific enforcement policies may be posted separately.

Project maintainers who do not follow or enforce the Code of Conduct in good faith may face temporary or permanent repercussions as determined by other members of the project's leadership.

# Attribution
[Attribution]: #attribution

This CONTRIBUTING.md was adapted from [ProjectPorcupine's](https://github.com/TeamPorcupine/ProjectPorcupine)'s [CONTRIBUTING.md](https://github.com/TeamPorcupine/ProjectPorcupine/blob/master/CONTRIBUTING.md).

The Code of Conduct was adapted from [PurpleBooth](https://github.com/PurpleBooth)'s [template for a good CONTRIBUTING.md](https://gist.github.com/PurpleBooth/b24679402957c63ec426), who adapted it from the [Contributor Covenant][homepage], version 1.4, available at [http://contributor-covenant.org/version/1/4][version].

[homepage]: http://contributor-covenant.org
[version]: http://contributor-covenant.org/version/1/4/