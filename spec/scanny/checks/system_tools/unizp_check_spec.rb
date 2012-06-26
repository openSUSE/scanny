require "spec_helper"

module Scanny::Checks::SystemTools
  describe UnzipCheck do
    before do
      @runner = Scanny::Runner.new(UnzipCheck.new)
      @message = "Unzip option allows '../' in archived file path, dir traversal"
      @issue_medium = issue(:medium, @message, [23, 88])
      @issue_high = issue(:high, @message, [23, 88])
    end

    it "reports \"system('unzip -tq *.zip')\" correctly" do
      @runner.should check("system('unzip -tq *.zip')").with_issue(@issue_medium)
    end

    it "reports \"`unzip -tq *.zip'`\" correctly" do
      @runner.should check("`unzip -tq *.zip'`").with_issue(@issue_medium)
    end

    it "reports \"system('unzip -: archive.zip ../../')\" correctly" do
      @runner.should  check("system('unzip -: archive.zip ../../')").
                      with_issue(@issue_high)
    end

    it "reports \"`unzip -: archive.zip ../../`\" correctly" do
      @runner.should check("`unzip -: archive.zip ../../`").with_issue(@issue_high)
    end
  end
end
