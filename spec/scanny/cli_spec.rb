require "spec_helper"

describe "Command line interface" do
  before(:all) do
    @help_message_prefix = "Scanny RoR secutiry scanner"
    @aruba_timeout_seconds = 10
  end

  after { FileUtils.rm_rf(File.expand_path("../../../tmp", __FILE__)) }

  describe "when given --help argument" do
    before { run 'scanny --help' }
    it { assert_partial_output @help_message_prefix, all_stdout }
    it { assert_exit_status 0 }
  end

  context "scan files" do
    before do
      write_file('app/test.rb', 'reset_session')
      write_file('app/test/sub_test.rb', 'reset_session')
    end

    describe "when given no argument" do
      before { run 'scanny' }

      it "scans all files in current app directory" do
        assert_matching_output "./app/test.rb", all_stdout
      end

      it "scans all files in subdirectories" do
        assert_matching_output "./app/test/sub_test.rb", all_stdout
      end

      it { assert_exit_status 1 }
    end

    describe "when given path argument" do
      before { run 'scanny ./app/test/' }

      it "scans all files in ./test directory" do
        assert_matching_output "./test/sub_test.rb", all_stdout
      end

      it "not scans files in current directory" do
        assert_no_partial_output "./test.rb", all_stdout
      end
    end
  end

  context "require checks" do
    before do
      write_file('./checks/check.rb', 'puts "check loaded"')
      write_file('./checks2/check.rb', 'puts "check2 loaded"')
      write_file('./app/project.rb', 'puts("hello world")')
    end

    describe "when given --include argument with one directory" do
      before { run 'scanny --include ./checks' }

      it { assert_partial_output "check loaded", all_stdout }
      it { assert_no_partial_output "check2 loaded", all_stdout }
      it { assert_exit_status 0 }
    end

    describe "when given --include argument with many directories" do
      before { run 'scanny --include ./checks,./checks2' }

      it { assert_partial_output "check loaded", all_stdout }
      it { assert_partial_output "check2 loaded", all_stdout }
      it { assert_exit_status 0 }
    end
  end

  context "disable checks" do
    before do
      @check_output = "[medium] ./security.rb:1: Use of external " +
                      "parameters in redirect_to methodcan lead to " +
                      "unauthorized redirects " +
                      "(CWE-79, CWE-113, CWE-601, CWE-698)"
      write_file("./security.rb", "redirect_to params[:input]")
    end

    describe "when all checks are enabled" do
      before { run 'scanny ./security.rb' }

      it { assert_partial_output @check_output, all_stdout }
      it { assert_exit_status 1 }
    end

    describe "when given --disable argument" do
      before { run 'scanny --disable Scanny::Checks::RedirectWithParamsCheck ./security.rb' }

      it { assert_no_partial_output @check_output, all_stdout }
      it { assert_exit_status 1 }
    end
  end

  context "reports" do
    before { write_file('test.rb', 'reset_session') }

    describe "when given -f xml argument" do
      before { run 'scanny -f xml ./test.rb' }
      it { check_directory_presence(['reports'], true) }
      it { check_file_presence(['reports/Test-.\\test.rb.xml'], true) }
      it { assert_exit_status 1 }
    end

    describe "when given -f strange_format argument" do
      before { run 'scanny -f strange_format ./test.rb' }
      it { assert_matching_output "Format strange_format is not supported", all_stderr }
      it { assert_exit_status 1 }
    end
  end

  context "strict" do
    before { write_file("check.rb", "42") }

    describe "when given --strict argument" do
      before { run 'scanny --strict --include ../../spec/support/checks ./check.rb' }
      it { assert_partial_output "strict checked", all_stdout }
      it { assert_exit_status 1 }
    end

    describe "when given no argument" do
      before { run 'scanny --include ../../spec/support/checks ./check.rb' }
      it { assert_no_partial_output "strict checked", all_stdout }
      it { assert_exit_status 1 }
    end
  end
end