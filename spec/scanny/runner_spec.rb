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
        checks.any? { |ch| ch.is_a?(Checks::XssSendCheck) }.should be_true
      end

      it "uses only \"leaf\" check classes" do
        checks = Runner.new.checks

        checks.any? { |ch| ch.class == Checks::ExtendCheck }.should be_false
        checks.any? { |ch| ch.class == Checks::MyCheck }.should be_true
      end
    end

    describe "check" do
      it "reports issues" do
        check_data = @runner.check("unsecure.rb", '42')

        check_data[:file].should   == 'unsecure.rb'
        check_data[:issues].should == [
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

      describe "ignore comments" do
        describe "SCANNY_IGNORE" do
          it "ignores lines with SCANNY_IGNORE" do
            @runner.should check('42 # SCANNY_IGNORE').without_issues
          end

          it "does not ignore lines before SCANNY_IGNORE" do
            @runner.should check(<<-EOT).with_n_issues(3)
              42
              boo # SCANNY_IGNORE
            EOT
          end

          it "does not ignore lines after SCANNY_IGNORE" do
            @runner.should check(<<-EOT).with_n_issues(3)
              boo # SCANNY_IGNORE
              42
            EOT
          end
        end

        describe "SCANNY_IGNORE_NEXT" do
          it "ignores line after SCANNY_IGNORE_NEXT" do
            @runner.should check(<<-EOT).without_issues
              boo # SCANNY_IGNORE_NEXT
              42
            EOT
          end

          it "does not ignore a line with SCANNY_IGNORE_NEXT" do
            @runner.should check(<<-EOT).with_n_issues(3)
              42 # SCANNY_IGNORE_NEXT
            EOT
          end

          it "does not ignore 2nd line after SCANNY_IGNORE_NEXT" do
            @runner.should check(<<-EOT).with_n_issues(3)
              boo # SCANNY_IGNORE_NEXT
              boo
              42
            EOT
          end
        end

        describe "SCANNY_IGNORE_NEXT_n" do
          it "ignores n lines after SCANNY_IGNORE_NEXT_n" do
            @runner.should check(<<-EOT).without_issues
              # SCANNY_IGNORE_NEXT_3
              42
              42
              42
            EOT
          end

          it "does not ignore a line with SCANNY_IGNORE_NEXT_n" do
            @runner.should check(<<-EOT).with_n_issues(3)
              42 # SCANNY_IGNORE_NEXT_3
            EOT
          end

          it "does not ignore (n+1)th line after SCANNY_IGNORE_NEXT_n" do
            @runner.should check(<<-EOT).with_n_issues(3)
              boo # SCANNY_IGNORE_NEXT_3
              boo
              boo
              boo
              42
            EOT
          end
        end
      end
    end

    # We don't test #check_file since it's just a tiny wrapper around #check.
  end
end
