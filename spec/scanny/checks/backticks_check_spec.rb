require "spec_helper"

module Scanny::Checks
  describe BackticksCheck do
    before :each do
      @runner = Scanny::Runner.new(BackticksCheck.new)
    end

    it "reports backticks without interpolation" do
      @runner.should parse('`ls -l`').with_issue(:high,
        "Backticks and %x{...} pass the executed command through shell expansion. (CWE-88,CWE-78)")
    end

    it "reports backticks with interpolation" do
      @runner.should parse('`ls #{options}`').with_issue(:high,
        "Backticks and %x{...} pass the executed command through shell expansion. (CWE-88,CWE-78)")
    end

    it "reports %x{...} without interpolation" do
      @runner.should parse('`ls -l`').with_issue(:high,
        "Backticks and %x{...} pass the executed command through shell expansion. (CWE-88,CWE-78)")
    end

    it "reports %x{...} with interpolation" do
      @runner.should parse('`ls #{options}`').with_issue(:high,
        "Backticks and %x{...} pass the executed command through shell expansion. (CWE-88,CWE-78)")
    end
  end
end
