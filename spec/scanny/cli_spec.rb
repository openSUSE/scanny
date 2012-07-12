require "spec_helper"

describe "Command line interface" do
  before { @help_message_prefix = "Scanny RoR secutiry scanner" }
  after { FileUtils.rm_rf(File.expand_path("../../../tmp", __FILE__)) }

  describe "when given --help argument" do
    before { run 'scanny --help' }
    it { assert_partial_output @help_message_prefix, all_stdout }
    it { assert_exit_status 0 }
  end

  context "scan files" do
    before do
      write_file('test.rb', 'reset_session')
      write_file('test/sub_test.rb', 'reset_session')
    end

    describe "when given no argument" do
      before { run 'scanny' }

      it "scans all files in current directory" do
        assert_matching_output "./test.rb", all_stdout
      end

      it "scans all files in subdirectories" do
        assert_matching_output "./test/sub_test.rb", all_stdout
      end

      it { assert_exit_status 1 }
    end

    describe "when given path argument" do
      before { run 'scanny ./test' }

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
    end

    describe "when given --include argument with one directory" do
      before { run 'scanny --include ./checks' }

      it { assert_partial_output "check loaded", all_stdout }
      it { assert_no_partial_output "check2 loaded", all_stdout }
      it { assert_exit_status 1 }
    end

    describe "when given --include argument with many directories" do
      before { run 'scanny --include ./checks,./checks2' }

      it { assert_partial_output "check loaded", all_stdout }
      it { assert_partial_output "check2 loaded", all_stdout }
      it { assert_exit_status 1 }
    end
  end

  context "disable checks" do
    before do
      @check_output = "[medium] ./security.rb:1: HTTP redirects can be " +
                      "emitted by the Application (CWE-601, CWE-698, CWE-79)"
      write_file("./security.rb", "redirect_to params[:input]")
    end

    describe "when all checks are enabled" do
      before { run 'scanny ./security.rb' }

      it { assert_partial_output @check_output, all_stdout }
      it { assert_exit_status 1 }
    end

    describe "when given --disable argument" do
      before { run 'scanny --disable Scanny::Checks::HTTPRedirectCheck ./security.rb' }

      it { assert_no_partial_output @check_output, all_stdout }
      it { assert_exit_status 1 }
    end
  end

  context "reports" do
    before { write_file('test.rb', 'reset_session') }

    describe "when given -f xml argument" do
      before { run 'scanny -f xml ./test.rb' }
      it { check_directory_presence(['reports'], true) }
      it { check_file_presence(['reports/Test-.\\test.rb.xml'], TRUE) }
      it { assert_exit_status 1 }
    end

    describe "when given -f strange_format argument" do
      before { run 'scanny -f strange_format ./test.rb' }
      it { assert_matching_output "Format strange_format is not supported", all_stderr }
      it { assert_exit_status 1 }
    end
  end
end