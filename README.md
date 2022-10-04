# snyk-job-summary-action


This Github Action gives the statistics of different kinds of vulnerabilities. Use this action to add a [Job Summary](https://github.blog/2022-05-09-supercharging-github-actions-with-job-summaries/) in GitHub Workflows.

## Usage

Add the following code to your GitHub Action

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

- name: Add Job Summary from Snyk reports
  uses: medly/snyk-job-summary-action@v1
  with:
      dependencies-report-path: snyk_dependencies.json # The file name of json file which is generated on snyk test
      code-report-path: snyk_code.json # The file name of json file which is generated on snyk code test
```
