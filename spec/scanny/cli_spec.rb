require "spec_helper"

describe "Command line interface" do
  before { @help_message_prefix = "Scanny RoR secutiry scanner" }
  after(:all) { FileUtils.rm_rf(File.expand_path("../../../tmp", __FILE__)) }

  describe "when given --version argument" do
    before { run 'scanny --version' }
    it { assert_matching_output Scanny::VERSION, all_stdout }
    it { assert_exit_status 0 }
  end

  describe "when given --help argument" do
    before { run 'scanny --help' }
    it { assert_partial_output @help_message_prefix, all_stdout }
    it { assert_exit_status 0 }
  end

  context "reports" do
    before { write_file('test.rb', 'class MyClass; end') }
    after do
      remove_dir('reports')
      remove_file('test.rb')
    end

    describe "when given -f xml argument" do
      before { run 'scanny -f xml' }
      it { assert_matching_output "Found no issues.", all_stdout }
      it { check_directory_presence(['reports'], true) }
      it { assert_exit_status 0 }
    end

    describe "when given -f strange_format argument" do
      before { run 'scanny -f strange_format' }
      it { assert_matching_output "Format strange_format is not supported", all_stdout }
      it { assert_exit_status 1 }
    end

    describe "when given -f xml -o output argument" do
      before { run 'scanny -f xml -o output' }
      it { assert_partial_output "Found no issues.", all_stdout }
      it { check_file_presence(['output'], true) }
      it { assert_exit_status 0 }
    end
  end
end