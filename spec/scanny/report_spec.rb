require "spec_helper"

module Scanny
  describe Report do

    describe "to_s" do
      describe "no issues" do
        it "returns correctly formatted string" do
          checks_performed = 5
          nodes_inspected  = 10

          report = Report.new 'foo.rb'
          report.checks_performed = checks_performed
          report.nodes_inspected  = nodes_inspected

          report.to_s.should == "foo.rb [#{checks_performed} checks done | "\
                                "#{nodes_inspected} nodes inspected | "\
                                "0 issues]"
        end
      end

      describe "has issues" do
        it "returns correctly formatted string" do
          checks_performed = 5
          nodes_inspected  = 10

          report = Report.new 'foo.rb'
          report.checks_performed = checks_performed
          report.nodes_inspected  = nodes_inspected
          report.issues << Issue.new("unsecure.rb", 42, :high, "Hey, I found unsecure code!", 43)
          report.issues << Issue.new("unsecure.rb", 43, :high, "Hey, I found unsecure code!", 43)

          expected_string = <<-EOT
foo.rb [#{checks_performed} checks done | #{nodes_inspected} nodes inspected | 2 issues]
  - [high] unsecure.rb:42: Hey, I found unsecure code! (CWE-43)
  - [high] unsecure.rb:43: Hey, I found unsecure code! (CWE-43)
EOT
          report.to_s.should == expected_string.chomp
        end
      end
    end
  end
end
