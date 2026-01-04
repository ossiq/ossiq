# Tutorials

This section provides hands-on, step-by-step guides to help you achieve a specific goal with OSS IQ. Each tutorial is a self-contained lesson designed to teach you core aspects of the tool by building something tangible.

---

### Analyzing Your First Project's Dependencies

**Goal:** To perform a complete dependency analysis on a sample project, from initial setup to exploring the final HTML report.

**What you'll learn:**

 - How to install and verify `ossiq-cli`.
 - How to run the `scan` command on a local project.
 - How to interpret the key metrics in the console output.
 - How to generate and navigate the interactive HTML report.

**Outline:**

 - **Step 1: Installation** (Todo)
 - **Step 2: Setting up the Sample Project** (Todo: Provide a git repo to clone)
 - **Step 3: Running Your First Analysis** (Todo: Show the `ossiq-cli scan` command)
 - **Step 4: Understanding the Console Output** (Todo: Briefly explain scores)
 - **Step 5: Generating and Exploring the HTML Report** (Todo: Show the `-p html` flag and what the report looks like)
 - **Next Steps** (Todo: Link to other docs)


### Integrating OSS IQ into a CI/CD Pipeline

**Goal:** To set up a GitHub Actions workflow that automatically scans a project with `ossiq-cli` and fails the build if a security policy is violated.

**What you'll learn:**

 - How to create a basic policy file.
 - How to configure a GitHub Actions workflow to run `ossiq-cli`.
 - How to use `ossiq-cli` as a quality gate to enforce standards.

**Outline:**

 - **Step 1: The Sample Project** (Todo)
 - **Step 2: Defining a Security Policy** (Todo: Create a simple `policy.yml`)
 - **Step 3: Creating the GitHub Actions Workflow** (Todo: Provide the `.github/workflows/main.yml` snippet)
 - **Step 4: Running the Workflow and Seeing it Pass** (Todo)
 - **Step 5: Introducing a Vulnerability and Watching it Fail** (Todo: Show how to add a bad dependency and see the build fail)
 - **Conclusion** (Todo)

---

### Creating a Custom Risk Profile with a Scoring Model

!!! warning
    This is future functionality and **is not implemented yet**.
    See more details and progress in [GH-9](https://github.com/ossiq/ossiq/issues/9).


**Goal:** To tailor OSS IQ's analysis by creating a custom scoring model that reflects your organization's specific risk priorities.

**What you'll learn:**

 - The basic structure of an OSS IQ configuration file.
 - How to adjust the weights of different scoring dimensions (e.g., prioritize maintenance over security).
 - How to apply the custom model to an analysis.

**Outline:**

 - **Step 1: Understanding the Default Scoring** (Todo: Link to reference)
 - **Step 2: Creating a `config.yml` File** (Todo: Show basic structure)
 - **Step 3: Adjusting Scoring Weights** (Todo: Show how to change weights in the config)
 - **Step 4: Running an Analysis with the Custom Model** (Todo: Show `--config` flag)
 - **Step 5: Comparing the Results** (Todo: Show how the scores differ)
 - **Conclusion** (Todo)