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
end