require "resources"

print("before: " .. resources.get("ALL", "cpu_utime"))
n = 0
while n <= 20000000 do
    n = n + 1
end
print("after: " .. resources.get("ALL", "cpu_utime"))
