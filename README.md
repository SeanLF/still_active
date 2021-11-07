# StillActive

Identify which of your dependencies are no longer under active development.

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
        --safe-range-end=YEARS       maximum number of years since last activity to be considered safe
        --warning-range-start=YEARS  minimum number of years since last activity to be considered worrying
        --warning-range-end=YEARS    maximum number of years since last activity to be considered worrying
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
stll_active --github-oauth-token=my-token-here
```

Outputs:

| gem activity old? | up to date? | name                                                           | version used                                                      | release date | latest version                                                    | release date | latest pre-release version                                           | release date | last commit date                                       |
| ----------------- | ----------- | -------------------------------------------------------------- | ----------------------------------------------------------------- | ------------ | ----------------------------------------------------------------- | ------------ | -------------------------------------------------------------------- | ------------ | ------------------------------------------------------ |
|                   | ✅           | [debug](https://github.com/ruby/debug)                         | [1.3.4](https://rubygems.org/gems/debug/versions/1.3.4)           | 2021/10      | [1.3.4](https://rubygems.org/gems/debug/versions/1.3.4)           | 2021/10      | [1.0.0.rc2](https://rubygems.org/gems/debug/versions/1.0.0.rc2)      | 2021/09      | [2021/11](https://github.com/ruby/debug)               |
|                   | ✅           | [rake](https://github.com/ruby/rake)                           | [13.0.6](https://rubygems.org/gems/rake/versions/13.0.6)          | 2021/07      | [13.0.6](https://rubygems.org/gems/rake/versions/13.0.6)          | 2021/07      | [13.0.0.pre.1](https://rubygems.org/gems/rake/versions/13.0.0.pre.1) | 2019/09      | [2021/07](https://github.com/ruby/rake)                |
| ⚠️                 | ✅           | [rspec](https://github.com/rspec/rspec)                        | [3.10.0](https://rubygems.org/gems/rspec/versions/3.10.0)         | 2020/10      | [3.10.0](https://rubygems.org/gems/rspec/versions/3.10.0)         | 2020/10      | [3.6.0.beta2](https://rubygems.org/gems/rspec/versions/3.6.0.beta2)  | 2016/12      | [2021/10](https://github.com/rspec/rspec)              |
|                   | ✅           | [rubocop](https://github.com/rubocop/rubocop)                  | [1.22.3](https://rubygems.org/gems/rubocop/versions/1.22.3)       | 2021/10      | [1.22.3](https://rubygems.org/gems/rubocop/versions/1.22.3)       | 2021/10      | ❓                                                                    | ❓            | [2021/11](https://github.com/rubocop/rubocop)          |
|                   | ✅           | [rubocop-shopify](https://github.com/Shopify/ruby-style-guide) | [2.3.0](https://rubygems.org/gems/rubocop-shopify/versions/2.3.0) | 2021/10      | [2.3.0](https://rubygems.org/gems/rubocop-shopify/versions/2.3.0) | 2021/10      | ❓                                                                    | ❓            | [2021/11](https://github.com/Shopify/ruby-style-guide) |
| ❓                 | ❓           | still_active                                                   | 0.1.0                                                             | ❓            | ❓                                                                 | ❓            | ❓                                                                    | ❓            | ❓                                                      |

### Configuration options

- `gemfile_path` uses bundler to detect the Gemfile in your working directory
- `output_format` is markdown, can be configured to be JSON
- `critical_warning_emoji` 🚩
- `futurist_emoji` 🔮
- `success_emoji` ✅
- `unsure_emoji` ❓
- `warning_emoji` ⚠️
- `safe_range_end` 1 (safe range is by default [0..1])
- `warning_range_start`  2 (warning range is by default [2..3])
- `warning_range_end`  3

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
