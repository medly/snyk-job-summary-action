# snyk-job-summary-action

Use this action to add a [Job Summary](https://github.blog/2022-05-09-supercharging-github-actions-with-job-summaries/) in GitHub Workflows.

## Usage

```yaml
...
- name: Run Snyk to check for vulnerabilities
  uses: snyk/actions/gradle-jdk11@master # See https://github.com/snyk/actions for other supported build tools/languages
  env:
    SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
  with:
    command: test --all-projects --json-file-output=snyk_code.json

- name: Add Job Summary from Snyk reports
  uses: medlypharmacy/snyk-job-summary-action@v1
```
