# 2011/09/12: slms/webapp/lib/external_program.rb Is this a true pos. or a true neg?
#
#  Copyright (c) 2009 Novell, Inc.
#  All Rights Reserved.
#
#  This library is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public License as
#  published by the Free Software Foundation; version 2.1 of the license.
#
#  This library is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.   See the
#  GNU Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this library; if not, contact Novell, Inc.
#
#  To contact Novell about this file by physical or electronic mail,
#  you may find current contact information at www.novell.com

# using popen4 because popen3 has a bug; it always yields $?.exitstatus == 0
# once this is fixed in ruby, we can drop popen4 (popen3 is part of standard
# ruby, popen4 is gem)
require 'open4'


class ExternalProgram

  include Slms::Task::Logger
  attr_accessor :success, :exit_value
  attr_accessor :name, :args
  attr_accessor :stdout, :stderr

  def initialize(name, args = [])
    @name = name
    @args = []
    args.each do |arg|
      @args.push arg.to_s
    end
    @stdin = []
    @outfile = nil
  end

  def stdin(input)
    if input.instance_of?(Array)
      @stdin = input
    else
      @stdin = [ input.to_s ]
    end
  end

  def run
    @stderr = ""
    @stdout = ""
    @exit_value = nil
    file = nil
    if !@outfile.nil? && !@outfile.empty?
      if !File.exist?( File.dirname(@outfile) )
        File.mkpath File.dirname(@outfile)
      end
      file = File.new(@outfile, "w")
    end

    logdebug("Executing command \"#{@name} #{@args.join(' ')}\"")
    counter = 0
    begin
      Open4.popen4(*[@name, *@args]) { |pid, stdin, out, err| # TESTCASE: CWE-78, CWE-88
        stdin.puts @stdin[counter] if @stdin[counter]
        counter += 1
        stdin.close
        out = out.read
        err = err.read
        if file
          file.write out
          file.write err
          file.flush
        end
        @stdout << out
        @stderr << err
      }

      @success = ($?.success? && $?.exitstatus == 0)
      @exit_value = $?.exitstatus

      # log result
      logdebug("Command \"#{@name}\" exited with status #{@exit_value}")
      if @stderr.any?
        logwarn("Error output of \"#{@name}\":\n#{@stderr}")
      end
      if @stdout.any?
        logdebug("Program output of \"#{@name}\":\n#{@stdout}")
      else
        logdebug("Program \"#{@name}\" had no output")
      end
    rescue Exception => e
      logerror("Command \"#{@name}\" failed to execute (#{e.message})") # RORSCAN_ITL
      @success = false
    end

    file.close if file

    return @success
  end

  # makes using ExternalProgram with DelayedJob smoother
  alias :perform :run

  def success?
    return @success
  end

  def output_to(filename)
    @outfile = filename
  end
end
