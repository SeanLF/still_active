# `still_active`

Identify which of your dependencies are no longer under active development.

[![Gem Version](https://badge.fury.io/rb/still_active.svg)](https://badge.fury.io/rb/still_active)

![Code Quality analysis](https://github.com/SeanLF/still_active/actions/workflows/codeql-analysis.yml/badge.svg)
![RSpec](https://github.com/SeanLF/still_active/actions/workflows/rspec.yml/badge.svg)
![Rubocop analysis](https://github.com/SeanLF/still_active/actions/workflows/rubocop-analysis.yml/badge.svg)

## Installation

```bash
gem install still_active
```

## Usage

The most important flag is the GitHub OAuth token, without which you will most certainly get rate limited.

```text
Usage: still_active [options]

        all flags are optional

        --gemfile=GEMFILE            path to gemfile
        --gems=GEM,GEM2,...          Gem(s)
        --markdown                   Prints output in markdown format
        --json                       Prints output in JSON format
        --github-oauth-token=TOKEN   GitHub OAuth token to make API calls
        --simultaneous-requests=QTY  Number of simultaneous requests made
        --no-warning-range-end=YEARS maximum number of years since last activity until which you do not want to be warned about 
        --warning-range-end=YEARS    maximum number of years since last activity that you want to be warned about
        --critical-warning-emoji=EMOJI
        --futurist-emoji=EMOJI
        --success-emoji=EMOJI
        --unsure-emoji=EMOJI
        --warning-emoji=EMOJI
    -h, --help                       Show this message
    -v, --version                    Show version
```

### Examples

```bash
still_active --json --gems=rails,nokogiri
```

Will output:

```json
{"rails":{"latest_version":"6.1.4.1","latest_version_release_date":"2021-08-19 16:27:05 UTC","latest_pre_release_version":"7.0.0.alpha2","latest_pre_release_version_release_date":"2021-09-15 23:16:26 UTC","repository_url":"https://github.com/rails/rails","last_commit_date":"2021-11-06 09:16:40 UTC","ruby_gems_url":"https://rubygems.org/gems/rails"},"nokogiri":{"latest_version":"1.12.5","latest_version_release_date":"2021-09-27 19:03:57 UTC","latest_pre_release_version":"1.12.0.rc1","latest_pre_release_version_release_date":"2021-07-09 20:00:11 UTC","repository_url":"https://github.com/sparklemotion/nokogiri","last_commit_date":"2021-11-06 16:44:55 UTC","ruby_gems_url":"https://rubygems.org/gems/nokogiri"}}
```

```bash
# for this gem
still_active --github-oauth-token=my-token-here
```

Outputs:

| gem activity old? | up to date? | name | version used | release date | latest version | release date | latest pre-release version  | release date | last commit date |
| ----------------- | ----------- | ---- | ------------ | ------------ | -------------- | ------------ | --------------------------- | ------------ | ---------------- |
| ⚠️ | ✅ | [code-scanning-rubocop](https://github.com/arthurnn/code-scanning-rubocop) | [0.6.1](https://rubygems.org/gems/code-scanning-rubocop/versions/0.6.1) | 2022/02 | [0.6.1](https://rubygems.org/gems/code-scanning-rubocop/versions/0.6.1) | 2022/02 | ❓ | ❓ | [2022/02](https://github.com/arthurnn/code-scanning-rubocop) |
|  | ✅ | [dead_end](https://github.com/zombocom/dead_end) | [4.0.0](https://rubygems.org/gems/dead_end/versions/4.0.0) | 2022/06 | [4.0.0](https://rubygems.org/gems/dead_end/versions/4.0.0) | 2022/06 | ❓ | ❓ | [2023/05](https://github.com/zombocom/dead_end) |
|  | ✅ | [debug](https://github.com/ruby/debug) | [1.8.0](https://rubygems.org/gems/debug/versions/1.8.0) | 2023/05 | [1.8.0](https://rubygems.org/gems/debug/versions/1.8.0) | 2023/05 | [1.0.0.rc2](https://rubygems.org/gems/debug/versions/1.0.0.rc2) | 2021/09 | [2023/05](https://github.com/ruby/debug) |
|  | ✅ | [faker](https://github.com/faker-ruby/faker) | [3.2.0](https://rubygems.org/gems/faker/versions/3.2.0) | 2023/04 | [3.2.0](https://rubygems.org/gems/faker/versions/3.2.0) | 2023/04 | ❓ | ❓ | [2023/05](https://github.com/faker-ruby/faker) |
|  | ✅ | [rake](https://github.com/ruby/rake) | [13.0.6](https://rubygems.org/gems/rake/versions/13.0.6) | 2021/07 | [13.0.6](https://rubygems.org/gems/rake/versions/13.0.6) | 2021/07 | [13.0.0.pre.1](https://rubygems.org/gems/rake/versions/13.0.0.pre.1) | 2019/09 | [2023/05](https://github.com/ruby/rake) |
|  | ✅ | [rspec](https://github.com/rspec/rspec-metagem) | [3.12.0](https://rubygems.org/gems/rspec/versions/3.12.0) | 2022/10 | [3.12.0](https://rubygems.org/gems/rspec/versions/3.12.0) | 2022/10 | [3.6.0.beta2](https://rubygems.org/gems/rspec/versions/3.6.0.beta2) | 2016/12 | [2022/10](https://github.com/rspec/rspec-metagem) |
|  | ✅ | [rubocop](https://github.com/rubocop/rubocop) | [1.51.0](https://rubygems.org/gems/rubocop/versions/1.51.0) | 2023/05 | [1.51.0](https://rubygems.org/gems/rubocop/versions/1.51.0) | 2023/05 | ❓ | ❓ | [2023/05](https://github.com/rubocop/rubocop) |
|  | ✅ | [rubocop-performance](https://github.com/rubocop/rubocop-performance) | [1.18.0](https://rubygems.org/gems/rubocop-performance/versions/1.18.0) | 2023/05 | [1.18.0](https://rubygems.org/gems/rubocop-performance/versions/1.18.0) | 2023/05 | ❓ | ❓ | [2023/05](https://github.com/rubocop/rubocop-performance) |
|  | ✅ | [rubocop-rspec](https://github.com/rubocop/rubocop-rspec) | [2.22.0](https://rubygems.org/gems/rubocop-rspec/versions/2.22.0) | 2023/05 | [2.22.0](https://rubygems.org/gems/rubocop-rspec/versions/2.22.0) | 2023/05 | [2.0.0.pre](https://rubygems.org/gems/rubocop-rspec/versions/2.0.0.pre) | 2020/10 | [2023/05](https://github.com/rubocop/rubocop-rspec) |
|  | ✅ | [rubocop-shopify](https://github.com/Shopify/ruby-style-guide) | [2.13.0](https://rubygems.org/gems/rubocop-shopify/versions/2.13.0) | 2023/04 | [2.13.0](https://rubygems.org/gems/rubocop-shopify/versions/2.13.0) | 2023/04 | ❓ | ❓ | [2023/05](https://github.com/Shopify/ruby-style-guide) |
|  | ⚠️ | [still_active](https://github.com/SeanLF/still_active) | [0.5.0](https://rubygems.org/gems/still_active/versions/0.5.0) | ❓ | [0.4.1](https://rubygems.org/gems/still_active/versions/0.4.1) | 2022/02 | ❓ | ❓ | [2023/05](https://github.com/SeanLF/still_active) |
|  | ✅ | [vcr](https://github.com/vcr/vcr) | [6.1.0](https://rubygems.org/gems/vcr/versions/6.1.0) | 2022/03 | [6.1.0](https://rubygems.org/gems/vcr/versions/6.1.0) | 2022/03 | [2.0.0.rc2](https://rubygems.org/gems/vcr/versions/2.0.0.rc2) | 2012/02 | [2023/01](https://github.com/vcr/vcr) |
|  | ✅ | [webmock](https://github.com/bblimke/webmock) | [3.18.1](https://rubygems.org/gems/webmock/versions/3.18.1) | 2022/08 | [3.18.1](https://rubygems.org/gems/webmock/versions/3.18.1) | 2022/08 | [2.0.0.beta2](https://rubygems.org/gems/webmock/versions/2.0.0.beta2) | 2016/04 | [2022/08](https://github.com/bblimke/webmock) |

### Configuration options

- `gemfile_path` uses bundler to detect the Gemfile in your working directory
- `output_format` is markdown, can be configured to be JSON
- `critical_warning_emoji` 🚩
- `futurist_emoji` 🔮
- `success_emoji` ✅
- `unsure_emoji` ❓
- `warning_emoji` ⚠️
- `no_warning_range_end` 1 (considered safe if last activity is at most 1 year ago)
- `warning_range_end`  3 (warns if last activity is between 1 and 3 years ago)

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
