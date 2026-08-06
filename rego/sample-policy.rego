package agent_policy

default AddARPNeighborsRequest := false
default AddSwapPathRequest := false
default AddSwapRequest := false
default CheckRequest := true
default CloseStdinRequest := false
default CopyFileRequest := false
CopyFileRequest if {
    allow_path(input.path)
    dir_mode := bits.lsh(1, 31)
    allowed_dir_permission := bits.or(dir_mode, 488)
    input.dir_mode == allowed_dir_permission
}
allow_path(path) if {
    regex.match("/run/kata-containers/shared/containers/[[:xdigit:]]+", path)
}

default CreateContainerRequest := false
# --- generator inserts CreateContainerRequest, allow_image, and allow_command rules here ---

default CreateSandboxRequest := true
default DestroySandboxRequest := true
default ExecProcessRequest := false
default GetDiagnosticDataRequest := false
default GetIPTablesRequest := false
default GetMetricsRequest := false
default GetOOMEventRequest := true
default GuestDetailsRequest := false
GuestDetailsRequest if {
    input.mem_block_size == true
    input.mem_hotplug_probe == true
}
default ListInterfacesRequest := false
default ListRoutesRequest := false
default MemAgentCompactConfig := false
default MemAgentMemcgConfig := false
default MemHotplugByProbeRequest := false
default OnlineCPUMemRequest := true
default PauseContainerRequest := false
default ReadStreamRequest := true
default RemoveContainerRequest := false
RemoveContainerRequest if {
    allow_startcontainer(input.container_id)
}
allow_startcontainer(container_id) if {
    regex.match("^[a-f0-9]{64}$", container_id)
}

default RemoveStaleVirtiofsShareMountsRequest := false
default ReseedRandomDevRequest := false
default ResizeVolumeRequest := false
default ResumeContainerRequest := false
default SetGuestDateTimeRequest := false
default SetIPTablesRequest := false
default SetPolicyRequest := false
default SignalProcessRequest := true
default StartContainerRequest := false
StartContainerRequest if {
    allow_startcontainer(input.container_id)
}

default StatsContainerRequest := true
default TtyWinResizeRequest := false
default UpdateContainerRequest := false
default UpdateEphemeralMountsRequest := true
default UpdateInterfaceRequest := true
default UpdateRoutesRequest := true
default VolumeStatsRequest := false
default WaitProcessRequest := true
default WriteStreamRequest := false
