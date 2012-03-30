require "resources"

function rget(r)
    now_scpu = resources.get("ALL", "cpu_stime")
    now_ucpu = resources.get("ALL", "cpu_utime")
    now_mem  = resources.get("ALL", "shared_mem")
    r:debug("Current System CPU: " .. now_scpu)
    r:debug("Current User CPU: " .. now_ucpu)
    r:debug("Current Memory: " .. now_mem)
end

