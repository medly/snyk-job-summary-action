# snyk-job-summary-action


This Github Action gives the statistics of different kinds of vulnerabilities. Use this action to add a [Job Summary](https://github.blog/2022-05-09-supercharging-github-actions-with-job-summaries/) in GitHub Workflows.

## Usage

To use this action, you will need to have a Snyk account and an API token. If you haven't already done so, sign up for a [free Snyk account](https://snyk.io/signup/), then [generate an API token](https://app.snyk.io/account/token).

To use this action in your project, add the following to your GitHub Actions workflow:

```yaml
...
- name: Run Snyk to check for vulnerabilities in dependencies
  uses: snyk/actions/gradle-jdk11@master # See https://github.com/snyk/actions for other supported build tools/languages
  continue-on-error: true
  env:
    SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
  with:
    command: test --all-projects --json-file-output=snyk_dependencies.json
          
- name: Run Snyk to check for vulnerabilities in code
  uses: snyk/actions/gradle-jdk11@master # See https://github.com/snyk/actions for other supported build tools/languages
  env:
    SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
  with:
    command: code test --all-projects --json-file-output=snyk_code.json

- name: Run Snyk to check Docker image for vulnerabilities
  uses: snyk/actions/docker@master # See https://github.com/snyk/actions for other supported build tools/languages
  env:
    SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
  with:
    image: your/image-to-test

- name: Add Job Summary from Snyk reports
  uses: medly/snyk-job-summary-action@v1
  with:
    DependenciesReportPath: snyk_dependencies.json # The file name of json file which is generated on snyk test
    CodeReportPath: snyk_code.json # The file name of json file which is generated on snyk code test
    ContainerReportPath: snyk_container.json # The file name of json file which is generated on snyk container test
    ArtifactName: snyk-details # The file name of the artifact which will be generated
```
This action performs the following steps:

- Runs a Snyk test to check for vulnerabilities in dependencies
- Runs a Snyk test to check for vulnerabilities in code
- Runs a Snyk test to check for vulnerabilities in container
- Generates JSON files for both dependencies and code tests
- Adds a job summary with the results of the Snyk tests

Note that this action is set to continue on error, so your workflow will not fail even if vulnerabilities are found.

## Inputs
`SNYK_TOKEN`: Your Snyk API token. This should be stored as a [GitHub secret](https://docs.github.com/en/actions/security-guides/encrypted-secrets).

## Contributing
We welcome contributions to this GitHub Action! To contribute, please create a pull request with your proposed changes.

## License
This GitHub Action is licensed under the [MIT License](https://chat.openai.com/LICENSE).
