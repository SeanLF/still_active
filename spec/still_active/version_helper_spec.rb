# frozen_string_literal: true

require "json"

RSpec.describe(StillActive::VersionHelper) do
  describe("#find_version") do
    context("when versions is nil") do
      subject { described_class.find_version(versions: versions) }

      let(:versions) { nil }

      it { is_expected.to(be_nil) }
    end

    context("when versions is valid") do
      subject { described_class.find_version(versions: versions, version_string: version_string, pre_release: pre_release) }

      let(:pre_release) { false }
      let(:version_string) { nil }
      let(:versions) do
        JSON.parse('[{"authors":"Koichi Sasada","built_at":"2021-10-29T00:00:00.000Z","created_at":"2021-10-29T07:21:16.042Z","description":"Debugging functionality for Ruby. This is completely rewritten debug.rb which was contained by the encient Ruby versions.","downloads_count":13698,"metadata":{"homepage_uri":"https://github.com/ruby/debug","source_code_uri":"https://github.com/ruby/debug"},"number":"1.3.4","summary":"Debugging functionality for Ruby","platform":"ruby","rubygems_version":"\u003e= 0","ruby_version":"\u003e= 2.6.0","prerelease":false,"licenses":["Ruby","BSD-2-Clause"],"requirements":[],"sha":"9b4852d2f84adedc14458e65d5ec597b911465258e911992bf1a9a95bcc124db"},{"authors":"Koichi Sasada","built_at":"2021-10-29T00:00:00.000Z","created_at":"2021-10-29T04:48:09.876Z","description":"Debugging functionality for Ruby. This is completely rewritten debug.rb which was contained by the encient Ruby versions.","downloads_count":354,"metadata":{"homepage_uri":"https://github.com/ruby/debug","source_code_uri":"https://github.com/ruby/debug"},"number":"1.3.3","summary":"Debugging functionality for Ruby","platform":"ruby","rubygems_version":"\u003e= 0","ruby_version":"\u003e= 2.6.0","prerelease":false,"licenses":["Ruby","BSD-2-Clause"],"requirements":[],"sha":"a122361038a7687c1dfe72b49ec98b378840d37ad16d8cd799940845be59a10d"},{"authors":"Koichi Sasada","built_at":"2021-10-28T00:00:00.000Z","created_at":"2021-10-28T06:57:47.985Z","description":"Debugging functionality for Ruby. This is completely rewritten debug.rb which was contained by the encient Ruby versions.","downloads_count":1705,"metadata":{"homepage_uri":"https://github.com/ruby/debug","source_code_uri":"https://github.com/ruby/debug"},"number":"1.3.2","summary":"Debugging functionality for Ruby","platform":"ruby","rubygems_version":"\u003e= 0","ruby_version":"\u003e= 2.6.0","prerelease":false,"licenses":["Ruby","BSD-2-Clause"],"requirements":[],"sha":"ed2237da3a2146365677e60a63d3296fd09032ba2cadaa950bd77606d2bfc74b"},{"authors":"Koichi Sasada","built_at":"2021-10-22T00:00:00.000Z","created_at":"2021-10-22T05:42:56.912Z","description":"Debugging functionality for Ruby. This is completely rewritten debug.rb which was contained by the encient Ruby versions.","downloads_count":20801,"metadata":{"homepage_uri":"https://github.com/ruby/debug","source_code_uri":"https://github.com/ruby/debug"},"number":"1.3.1","summary":"Debugging functionality for Ruby","platform":"ruby","rubygems_version":"\u003e= 0","ruby_version":"\u003e= 2.6.0","prerelease":false,"licenses":["Ruby","BSD-2-Clause"],"requirements":[],"sha":"ccc6eddc33c158811fbae58c8f235cbdf08903f6d66b9085684b2c3dd7600fae"},{"authors":"Koichi Sasada","built_at":"2021-10-20T00:00:00.000Z","created_at":"2021-10-20T06:12:15.285Z","description":"Debugging functionality for Ruby. This is completely rewritten debug.rb which was contained by the encient Ruby versions.","downloads_count":8169,"metadata":{"homepage_uri":"https://github.com/ruby/debug","source_code_uri":"https://github.com/ruby/debug"},"number":"1.3.0","summary":"Debugging functionality for Ruby","platform":"ruby","rubygems_version":"\u003e= 0","ruby_version":"\u003e= 2.6.0","prerelease":false,"licenses":["Ruby","BSD-2-Clause"],"requirements":[],"sha":"6fee1c583075ee58bbc8c77b088ff44b9d6fde3a53278bf3bee3e2323bfc1d33"},{"authors":"Koichi Sasada","built_at":"2021-10-05T00:00:00.000Z","created_at":"2021-10-05T13:18:13.252Z","description":"Debugging functionality for Ruby. This is completely rewritten debug.rb which was contained by the encient Ruby versions.","downloads_count":33055,"metadata":{"homepage_uri":"https://github.com/ruby/debug","source_code_uri":"https://github.com/ruby/debug"},"number":"1.2.4","summary":"Debugging functionality for Ruby","platform":"ruby","rubygems_version":"\u003e= 0","ruby_version":"\u003e= 2.6.0","prerelease":false,"licenses":["Ruby","BSD-2-Clause"],"requirements":[],"sha":"befdd776f78e44fd762ce4a9b767934eafa45596ce11f70b5eb27eb4b7fac08b"},{"authors":"Koichi Sasada","built_at":"2021-10-05T00:00:00.000Z","created_at":"2021-10-05T03:19:13.346Z","description":"Debugging functionality for Ruby. This is completely rewritten debug.rb which was contained by the encient Ruby versions.","downloads_count":1298,"metadata":{"homepage_uri":"https://github.com/ruby/debug","source_code_uri":"https://github.com/ruby/debug"},"number":"1.2.3","summary":"Debugging functionality for Ruby","platform":"ruby","rubygems_version":"\u003e= 0","ruby_version":"\u003e= 2.6.0","prerelease":false,"licenses":["Ruby","BSD-2-Clause"],"requirements":[],"sha":"16ecf1fb3b39fc73ba7db1b8d2d2941f6f749028eeaefb1db8bf90bc821312c2"},{"authors":"Koichi Sasada","built_at":"2021-10-01T00:00:00.000Z","created_at":"2021-10-01T05:45:53.052Z","description":"Debugging functionality for Ruby. This is completely rewritten debug.rb which was contained by the encient Ruby versions.","downloads_count":4346,"metadata":{"homepage_uri":"https://github.com/ruby/debug","source_code_uri":"https://github.com/ruby/debug"},"number":"1.2.2","summary":"Debugging functionality for Ruby","platform":"ruby","rubygems_version":"\u003e= 0","ruby_version":"\u003e= 2.6.0","prerelease":false,"licenses":["Ruby","BSD-2-Clause"],"requirements":[],"sha":"6f564319d522f7a88fe0aa884d62779c9c76cf8471c3c9839f523ec844c96a18"},{"authors":"Koichi Sasada","built_at":"2021-09-30T00:00:00.000Z","created_at":"2021-09-30T05:37:36.329Z","description":"Debugging functionality for Ruby. This is completely rewritten debug.rb which was contained by the encient Ruby versions.","downloads_count":2905,"metadata":{"homepage_uri":"https://github.com/ruby/debug","source_code_uri":"https://github.com/ruby/debug"},"number":"1.2.1","summary":"Debugging functionality for Ruby","platform":"ruby","rubygems_version":"\u003e= 0","ruby_version":"\u003e= 2.6.0","prerelease":false,"licenses":["Ruby","BSD-2-Clause"],"requirements":[],"sha":"a6e5b0719901d3fdb081618de03df71618c375e3e7557ad5e48ea8429c196f51"},{"authors":"Koichi Sasada","built_at":"2021-09-29T00:00:00.000Z","created_at":"2021-09-29T08:19:58.743Z","description":"Debugging functionality for Ruby. This is completely rewritten debug.rb which was contained by the encient Ruby versions.","downloads_count":1846,"metadata":{"homepage_uri":"https://github.com/ruby/debug","source_code_uri":"https://github.com/ruby/debug"},"number":"1.2.0","summary":"Debugging functionality for Ruby","platform":"ruby","rubygems_version":"\u003e= 0","ruby_version":"\u003e= 2.6.0","prerelease":false,"licenses":["Ruby","BSD-2-Clause"],"requirements":[],"sha":"eff73ba732629f0448bbced9f0b09c4e862b7dca93c01bf2868e63018b323878"},{"authors":"Koichi Sasada","built_at":"2021-09-14T00:00:00.000Z","created_at":"2021-09-14T07:52:50.017Z","description":"Debugging functionality for Ruby. This is completely rewritten debug.rb which was contained by the encient Ruby versions.","downloads_count":10252,"metadata":{"homepage_uri":"https://github.com/ruby/debug","source_code_uri":"https://github.com/ruby/debug"},"number":"1.1.0","summary":"Debugging functionality for Ruby","platform":"ruby","rubygems_version":"\u003e= 0","ruby_version":"\u003e= 2.6.0","prerelease":false,"licenses":["Ruby","BSD-2-Clause"],"requirements":[],"sha":"d51e2933548e4ad2ef5aa2e0bda9747695877d3fe5f5b3dd6e7a2a396e459f5f"},{"authors":"Koichi Sasada","built_at":"2021-09-08T00:00:00.000Z","created_at":"2021-09-08T16:25:30.074Z","description":"Debugging functionality for Ruby. This is completely rewritten debug.rb which was contained by the encient Ruby versions.","downloads_count":5452,"metadata":{"homepage_uri":"https://github.com/ruby/debug","source_code_uri":"https://github.com/ruby/debug"},"number":"1.0.0","summary":"Debugging functionality for Ruby","platform":"ruby","rubygems_version":"\u003e= 0","ruby_version":"\u003e= 2.6.0","prerelease":false,"licenses":["Ruby","BSD-2-Clause"],"requirements":[],"sha":"d60844ab9efef27f5a726de17113d584349648018420d54eddc8d3540e826294"},{"authors":"Koichi Sasada","built_at":"2021-09-03T00:00:00.000Z","created_at":"2021-09-03T07:53:40.032Z","description":"Debugging functionality for Ruby. This is completely rewritten debug.rb which was contained by the encient Ruby versions.","downloads_count":756,"metadata":{"homepage_uri":"https://github.com/ruby/debug","source_code_uri":"https://github.com/ruby/debug"},"number":"1.0.0.rc2","summary":"Debugging functionality for Ruby","platform":"ruby","rubygems_version":"\u003e 1.3.1","ruby_version":"\u003e= 2.6.0","prerelease":true,"licenses":["Ruby","BSD-2-Clause"],"requirements":[],"sha":"75639be1522013872a861d6e345c121cdd83be8a015cc2b82c5ca5bccc99c983"},{"authors":"Koichi Sasada","built_at":"2021-09-03T00:00:00.000Z","created_at":"2021-09-03T05:58:34.505Z","description":"Debugging functionality for Ruby. This is completely rewritten debug.rb which was contained by the encient Ruby versions.","downloads_count":275,"metadata":{"homepage_uri":"https://github.com/ruby/debug","source_code_uri":"https://github.com/ruby/debug"},"number":"1.0.0.rc1","summary":"Debugging functionality for Ruby","platform":"ruby","rubygems_version":"\u003e 1.3.1","ruby_version":"\u003e= 2.6.0","prerelease":true,"licenses":["Ruby","BSD-2-Clause"],"requirements":[],"sha":"eaef1ddee88890454d1825cf1506d8807fcb40db219ce5c4a4fcbe7e95b6c8e5"},{"authors":"Koichi Sasada","built_at":"2021-07-14T00:00:00.000Z","created_at":"2021-07-14T19:57:49.622Z","description":"Debugging functionality for Ruby. This is completely rewritten debug.rb which was contained by the encient Ruby versions.","downloads_count":1104,"metadata":{"homepage_uri":"https://github.com/ruby/debug","source_code_uri":"https://github.com/ruby/debug"},"number":"1.0.0.beta8","summary":"Debugging functionality for Ruby","platform":"ruby","rubygems_version":"\u003e 1.3.1","ruby_version":"\u003e= 2.6.0","prerelease":true,"licenses":["Ruby","BSD-2-Clause"],"requirements":[],"sha":"4f0e761bc7b9d896ac9f38df1653e4703c5db73736d3ab126b09239e9f7cb605"},{"authors":"Koichi Sasada","built_at":"2021-07-13T00:00:00.000Z","created_at":"2021-07-13T04:52:38.329Z","description":"Debugging functionality for Ruby. This is completely rewritten debug.rb which was contained by the encient Ruby versions.","downloads_count":398,"metadata":{"homepage_uri":"https://github.com/ruby/debug","source_code_uri":"https://github.com/ruby/debug"},"number":"1.0.0.beta7","summary":"Debugging functionality for Ruby","platform":"ruby","rubygems_version":"\u003e 1.3.1","ruby_version":"\u003e= 2.6.0","prerelease":true,"licenses":["Ruby","BSD-2-Clause"],"requirements":[],"sha":"44fa379e3063c43ce68c910c9072bb3307494901b988052a98d546c0fd429784"},{"authors":"Koichi Sasada","built_at":"2021-07-07T00:00:00.000Z","created_at":"2021-07-07T02:33:37.359Z","description":"Debugging functionality for Ruby. This is completely rewritten debug.rb which was contained by the encient Ruby versions.","downloads_count":426,"metadata":{"homepage_uri":"https://github.com/ruby/debug","source_code_uri":"https://github.com/ruby/debug"},"number":"1.0.0.beta6","summary":"Debugging functionality for Ruby","platform":"ruby","rubygems_version":"\u003e 1.3.1","ruby_version":"\u003e= 2.6.0","prerelease":true,"licenses":["Ruby","BSD-2-Clause"],"requirements":[],"sha":"d2546d2bd592774a440cc838ad31b0501aee281cc84ae2e4a2b1b882bacc5330"},{"authors":"Koichi Sasada","built_at":"2021-06-17T00:00:00.000Z","created_at":"2021-06-17T16:55:25.861Z","description":"Debugging functionality for Ruby. This is completely rewritten debug.rb which was contained by the encient Ruby versions.","downloads_count":556,"metadata":{"homepage_uri":"https://github.com/ruby/debug","source_code_uri":"https://github.com/ruby/debug"},"number":"1.0.0.beta5","summary":"Debugging functionality for Ruby","platform":"ruby","rubygems_version":"\u003e 1.3.1","ruby_version":"\u003e= 2.6.0","prerelease":true,"licenses":["Ruby","BSD-2-Clause"],"requirements":[],"sha":"81d52207a84badb05edec95b73b94727bcca1f08e61fc61cf0378b77f8314e3e"},{"authors":"Koichi Sasada","built_at":"2021-05-25T00:00:00.000Z","created_at":"2021-05-25T06:16:44.364Z","description":"Debugging functionality for Ruby. This is completely rewritten debug.rb which was contained by the encient Ruby versions.","downloads_count":502,"metadata":{"homepage_uri":"https://github.com/ruby/debug","source_code_uri":"https://github.com/ruby/debug"},"number":"1.0.0.beta4","summary":"Debugging functionality for Ruby","platform":"ruby","rubygems_version":"\u003e 1.3.1","ruby_version":"\u003e= 2.6.0","prerelease":true,"licenses":["Ruby","BSD-2-Clause"],"requirements":[],"sha":"b01cf7a053b05bab1d4b8be8fa4d58296880ad7e9e1a6af6cd3872e0d00a358b"},{"authors":"Koichi Sasada","built_at":"2021-05-14T00:00:00.000Z","created_at":"2021-05-14T05:43:29.021Z","description":"Debugging functionality for Ruby. This is completely rewritten debug.rb which was contained by the encient Ruby versions.","downloads_count":532,"metadata":{"homepage_uri":"https://github.com/ruby/debug","source_code_uri":"https://github.com/ruby/debug"},"number":"1.0.0.beta3","summary":"Debugging functionality for Ruby","platform":"ruby","rubygems_version":"\u003e 1.3.1","ruby_version":"\u003e= 2.6.0","prerelease":true,"licenses":["Ruby","BSD-2-Clause"],"requirements":[],"sha":"52cd54ba0706957ab327c0448212e043a9b6418231f49a2f85dffef138ec8ccd"},{"authors":"Koichi Sasada","built_at":"2021-05-10T00:00:00.000Z","created_at":"2021-05-10T03:21:59.651Z","description":"Debugging functionality for Ruby. This is completely rewritten debug.rb which was contained by the encient Ruby versions.","downloads_count":516,"metadata":{"homepage_uri":"https://github.com/ruby/debug","source_code_uri":"https://github.com/ruby/debug"},"number":"1.0.0.beta2","summary":"Debugging functionality for Ruby","platform":"ruby","rubygems_version":"\u003e 1.3.1","ruby_version":"\u003e= 2.6.0","prerelease":true,"licenses":["Ruby","BSD-2-Clause"],"requirements":[],"sha":"70a33e840b0f3b84e90862f1ba7a91879517edd2b165440bebf9c6b1446a9bef"},{"authors":"Koichi Sasada","built_at":"2021-05-07T00:00:00.000Z","created_at":"2021-05-07T08:59:53.344Z","description":"Debugging functionality for Ruby. This is completely rewritten debug.rb which was contained by the encient Ruby versions.","downloads_count":520,"metadata":{"homepage_uri":"https://github.com/ruby/debug","source_code_uri":"https://github.com/ruby/debug"},"number":"1.0.0.beta1","summary":"Debugging functionality for Ruby","platform":"ruby","rubygems_version":"\u003e 1.3.1","ruby_version":"\u003e= 2.6.0","prerelease":true,"licenses":["Ruby","BSD-2-Clause"],"requirements":[],"sha":"4f6a6ca138d1dad8084a69b7d0078ec84a5c65ca7977083b7b0aafb67fbbe616"},{"authors":"Koichi Sasada","built_at":"2021-04-07T00:00:00.000Z","created_at":"2021-04-07T09:48:53.294Z","description":"debug.rb","downloads_count":581,"metadata":{"homepage_uri":"https://github.com/ko1/debug","source_code_uri":"https://github.com/ko1/debug"},"number":"1.0.0.alpha1","summary":"debug.rb","platform":"ruby","rubygems_version":"\u003e 1.3.1","ruby_version":"\u003e= 2.6.0","prerelease":true,"licenses":["MIT"],"requirements":[],"sha":"730aeadc4519866ef80ebd5c4b4d5f12f9f9e7a789bdffa5c1b155b73af8b292"},{"authors":"Koichi Sasada","built_at":"2021-04-07T00:00:00.000Z","created_at":"2021-04-07T08:58:06.960Z","description":"debug.rb","downloads_count":565,"metadata":{"homepage_uri":"https://github.com/ko1/debug","source_code_uri":"https://github.com/ko1/debug"},"number":"1.0.0.alpha0","summary":"debug.rb","platform":"ruby","rubygems_version":"\u003e 1.3.1","ruby_version":"\u003e= 2.6.0","prerelease":true,"licenses":["MIT"],"requirements":[],"sha":"026883c55bdb258de8b84f6b710e7bd9273c4641a7abcb4f2a4094985cccdfb7"},{"authors":"Yukihiro Matsumoto","built_at":"2021-03-17T00:00:00.000Z","created_at":"2021-03-17T04:23:11.571Z","description":"Debugging functionality for Ruby","downloads_count":27938,"metadata":{"homepage_uri":"https://github.com/ruby/debug","source_code_uri":"https://github.com/ruby/debug"},"number":"0.2.0","summary":"Debugging functionality for Ruby","platform":"ruby","rubygems_version":"\u003e= 0","ruby_version":"\u003e= 2.3.0","prerelease":false,"licenses":["Ruby","BSD-2-Clause"],"requirements":[],"sha":"7dbba5e0d04950f29eb79ce1e7c95d15448690f9dd22652ec127e2f208ca7722"}]')
      end

      context("when a version string is specified") do
        let(:version_string) { "1.3.4" }

        context("when pre-release is requested") do
          let(:pre_release) { true }

          it { is_expected.to(be_nil) }
        end

        context("when no pre-release is specified") do
          it { is_expected.to(eq(versions.first)) }
        end
      end

      context("when a version string is not specified") do
        context("when pre-release is requested") do
          let(:pre_release) { true }

          it { is_expected.to(eq(versions[12])) }
        end

        context("when no pre-release is specified") do
          it { is_expected.to(eq(versions.first)) }
        end
      end
    end
  end

  describe("#up_to_date?") do
    let(:test_cases) do
      [
        { version_used: nil, latest_version: nil, latest_pre_release_version: nil },
        { version_used: "1.0.0", latest_version: nil, latest_pre_release_version: nil },
        { version_used: "1.0.0", latest_version: "1.0.0", latest_pre_release_version: "3.0.0rc1" },
        { version_used: "1.0.0", latest_version: "1.0.0", latest_pre_release_version: nil },
        { version_used: "1.0.0", latest_version: nil, latest_pre_release_version: "3.0.0rc1" },
        { version_used: "1.0.0", latest_version: "2.0.0", latest_pre_release_version: "3.0.0rc1" },
        { version_used: "1.0.0", latest_version: "2.0.0", latest_pre_release_version: nil },
        { version_used: "1.0.0", latest_version: nil, latest_pre_release_version: "3.0.0rc1" },
        { version_used: "3.0.0rc1", latest_version: "2.0.0", latest_pre_release_version: "3.0.0rc1" },
        { version_used: "3.0.0rc1", latest_version: nil, latest_pre_release_version: "3.0.0rc1" },
      ]
    end
    let(:expected_results) { [nil, nil, true, true, false, false, false, false, true, true] }

    it("returns the right result") do
      test_cases.each_with_index do |test_case, index|
        subject = described_class.up_to_date?(**test_case)
        expected_result = expected_results[index]

        expect(subject).to(eq(expected_result))
      end
    end
  end

  describe("#gem_version") do
    subject { described_class.gem_version(version_hash: version_hash) }

    context("when version_hash is nil") do
      let(:version_hash) { nil }

      it { is_expected.to(be_nil) }
    end

    context("when version hash is not nil") do
      let(:version_hash) { JSON.parse('{"authors":"Sean Floyd","built_at":"2021-11-07T00:00:00.000Z","created_at":"2021-11-07T13:07:51.346Z","description":"Obtain last release, pre-release, and last commit date to determine if a gem is still under active development.","downloads_count":52,"metadata":{"homepage_uri":"https://github.com/SeanLF/still_active.","changelog_uri":"https://github.com/SeanLF/still_active./blob/main/CHANGELOG.md","source_code_uri":"https://github.com/SeanLF/still_active."},"number":"0.1.0","summary":"Check if gems are under active development.","platform":"ruby","rubygems_version":"\u003e= 0","ruby_version":"\u003e= 2.4.0","prerelease":false,"licenses":["MIT"],"requirements":[],"sha":"e582da6edc04e43149345d23d12784a3d96081cf69e92bf5ae6ee0f42873a819"}') }

      it { is_expected.to(eq("0.1.0")) }
    end
  end

  describe("#release_date") do
    subject { described_class.release_date(version_hash: version_hash) }

    context("when version hash is nil") do
      let(:version_hash) { nil }

      it { is_expected.to(be_nil) }
    end

    context("when version hash is not nil") do
      let(:version_hash) { JSON.parse('{"authors":"Sean Floyd","built_at":"2021-11-07T00:00:00.000Z","created_at":"2021-11-07T13:07:51.346Z","description":"Obtain last release, pre-release, and last commit date to determine if a gem is still under active development.","downloads_count":52,"metadata":{"homepage_uri":"https://github.com/SeanLF/still_active.","changelog_uri":"https://github.com/SeanLF/still_active./blob/main/CHANGELOG.md","source_code_uri":"https://github.com/SeanLF/still_active."},"number":"0.1.0","summary":"Check if gems are under active development.","platform":"ruby","rubygems_version":"\u003e= 0","ruby_version":"\u003e= 2.4.0","prerelease":false,"licenses":["MIT"],"requirements":[],"sha":"e582da6edc04e43149345d23d12784a3d96081cf69e92bf5ae6ee0f42873a819"}') }
      let(:release_date) { Time.parse("2021-11-07T13:07:51.346Z") }

      it { is_expected.to(eq(release_date)) }
    end
  end
end
