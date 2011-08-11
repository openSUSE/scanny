require "spec_helper"

module Scanny
  describe Runner do
    before :each do
      @check = Checks::TestCheck.new
      @runner = Runner.new(@check)
    end

    describe "initialize" do
      it "uses passed checks when they are passed" do
        @runner.checks.should == [@check]
      end

      it "uses default checks when no checks are passed" do
        checks = Runner.new.checks

        checks.any? { |ch| ch.is_a?(Checks::TestCheck) }.should be_true
        checks.any? { |ch| ch.is_a?(Checks::XssCheck) }.should be_true
      end
    end

    describe "check" do
      it "reports issues" do
        report = @runner.check("unsecure.rb", '42')

        report.file.should   == 'unsecure.rb'
        report.issues.should == [
          Issue.new("unsecure.rb", 1, :high, "Hey, I found unsecure code!", 42),
          Issue.new("unsecure.rb", 1, :high, "Hey, I found more unsecure code!", 43),
          Issue.new("unsecure.rb", 1, :low,  "OK, this is unsecure too, but not that much")
        ]
      end

      it "raises SyntaxError when the input can't be parsed as Ruby code" do
        lambda {
          @runner.check("rubbish.rb", "@$%")
        }.should raise_error(SyntaxError)
      end
    end

    # We don't test #check_file since it's just a tiny wrapper around #check.
  end
end
