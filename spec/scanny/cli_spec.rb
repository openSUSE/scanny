require "spec_helper"

describe "Command line interface" do
  before { @help_message_prefix = "Scanny RoR secutiry scanner" }

  describe "when given --help argument" do
    before { run 'scanny --help' }
    it { assert_partial_output @help_message_prefix, all_stdout }
    it { assert_exit_status 0 }
  end
end