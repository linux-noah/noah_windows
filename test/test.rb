#!/usr/bin/env ruby

require "open3"
require "shellwords"
require "pathname"
require 'rbconfig'
require 'optparse'

@assertion = {pass: 0, fail: 0, premature: 0}
@assertion_reports = []
@stdout = {pass: 0, fail: 0, premature: 0}
@stdout_reports = []
@shell = {pass: 0, fail: 0, premature: 0}
@shell_reports = []

@options = {}

def main
  opts = OptionParser.new
  opts.banner = "Usage: test.rb path_to_noah_executable [test_cases..]"
  opts.on("-v", "--verbose", "Show verbose outputs") {|v| @options[:verbose] = v}
  opts.on("-aARCH", "--arch=ARCH", "Test testcases for architecture ARCH") {|a| @options[:arch] = a}
  opts.on("-h", "--help", "Print this help") do
    puts opts
    exit
  end
  opts.parse!
  @options[:noah_binname] = ARGV.shift
  if @options[:noah_binname].nil?
    STDERR.puts "path_to_noah_executable is missing"
    puts opts
    exit 1
  end
  targets = ARGV.empty? ? nil : ARGV
  puts <<-"EOS"

===============
Test Starts
===============

  EOS
  test_assertion(targets)
  test_stdout(targets)
  test_shell(targets)
  puts("")
  report()
end

def relative(path)
  p = Pathname.new(path)
  p.relative_path_from(Pathname.new(Dir.pwd)).to_s
end

def puts_testname(target)
  puts "\n===#{File.basename(target)}" if @options[:verbose]
end

def noah_binname
  @options[:noah_binname] + " --mnt=\"#{__dir__}/testing_root\""
end

def arch_dirname
  return @options[:arch] if @options[:arch]
  case RbConfig::CONFIG['host_os']
  when /mswin|msys|mingw|cygwin/
    "Windows"
  when /darwin|mac os/
    "Darwin"
  when /linux/
    "Linux"
  else
    raise 'Unsupported OS'
  end
end

def collect_tests(test_dirname)
  Dir.glob(__dir__ + "/#{test_dirname}/build/*") \
    + Dir.glob(__dir__ + "/arch/#{arch_dirname}/#{test_dirname}/build/*")
end

def test_assertion(targets = nil)
  collect_tests("test_assertion").each do |target|
    next if targets && !targets.include?(File.basename(target))
    puts_testname(target)
    out, err, status = Open3.capture3("#{noah_binname} #{relative(target).shellescape}")
    
    nr_tests_match = /1->([0-9]+)/.match(out.lines[0])
    if nr_tests_match
      nr_tests = nr_tests_match[1].to_i
    else
      nr_tests = -1 # It seems that the test crashed
    end

    print(out.lines[1..-1].join("")) if out.lines.length > 0

    passes = out.chars.count(".")
    fails = out.chars.count("F")
    is_premature = !status.success? || nr_tests != out.chars.count(".") + out.chars.count("F")

    @assertion[:pass] += passes
    @assertion[:fail] += fails
    if is_premature
      @assertion[:premature] += 1
      print("X")
    end

    if fails > 0 || is_premature
      @assertion_reports << {name: File.basename(target), diff: ["(diff unavailable)", "(diff unavailable)"], err: err, premature: is_premature}
    end
  end
end

def test_stdout(targets = nil)
  collect_tests("test_stdout").each do |target|
    next if targets && !targets.include?(File.basename(target))
    puts_testname(target)
    testdata_base = __dir__ + "/test_stdout/" + File.basename(target)
    target_stdin = File.exists?(testdata_base + ".stdin") ? (testdata_base + ".stdin").shellescape : "/dev/null"
    target_arg = File.exists?(testdata_base + ".arg") ? File.read(testdata_base + ".arg") : ""
    expected = File.read(testdata_base + ".expected")
    out, err, status = Open3.capture3("#{noah_binname} #{relative(target).shellescape} #{target_arg} < #{target_stdin}")

    if out == expected
      @stdout[:pass] += 1
      print(".")
    elsif status.success?
      @stdout[:fail] += 1
      print("F")
    else
      @stdout[:premature] += 1
      print("X")
    end

    unless err.empty? && status.success? && out == expected
      @stdout_reports << {name: File.basename(target), diff: [expected, out], err: err, premature: !status.success?}
    end
  end
end

def test_shell(targets = nil)
  collect_tests("test_shell").each do |target|
    next if targets && !targets.include?(File.basename(target))
    puts_testname(target)
    run = __dir__ + "/test_shell/" + File.basename(target) + ".sh"

    _, err, status = Open3.capture3("NOAH=\"#{noah_binname}\" TARGET=#{relative(target).shellescape} /bin/bash #{relative(run).shellescape}")

    if status.success?
      @shell[:pass] += 1
      print(".")
    else
      @shell[:fail] += 1
      print("F")
    end

    unless err.empty? && status.success?
      @shell_reports << {name: File.basename(target), diff: ["(diff unavailable)", "(diff unavailable)"], err: err, premature: false}
    end
  end
end

def report
  puts("")
  (@assertion_reports + @stdout_reports + @shell_reports).each_with_index do |report, i|
    puts("#{i}) #{report[:name]}")
    puts(report[:err]) unless report[:err].empty?
    if report[:diff] && report[:diff][0] != report[:diff][1]
      puts "== Expected"
      puts report[:diff][0]
      puts "== Actual"
      puts report[:diff][1]
      puts "=="
    end
    puts(report[:name] + " stopped prematurely!!") if report[:premature]
  end

  puts <<-"EOS"

===============
Assertion Test:
  Pass: #{@assertion[:pass]}, Fail: #{@assertion[:fail]}
  Premature Test Programs: #{@assertion[:premature]}
  Total Assertions: #{@assertion[:pass] + @assertion[:fail]}
Output Test:
  Pass: #{@stdout[:pass]}, Fail: #{@stdout[:fail]}
  Premature Test Programs: #{@stdout[:premature]}
  Total Test Programs: #{@stdout.values.reduce(&:+)}
Shell Test:
  Pass: #{@shell[:pass]}, Fail: #{@shell[:fail]}
  Total Test Programs: #{@shell.values.reduce(&:+)}
  EOS
end

main
if [@assertion, @stdout, @shell].inject(0) {|sum, v| sum + v[:fail] + v[:premature]} > 0
  exit(1)
end
