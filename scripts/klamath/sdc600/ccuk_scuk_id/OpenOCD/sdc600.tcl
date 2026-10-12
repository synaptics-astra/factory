
proc encode_sdc600_data {byte_list} {
    set encoded_list {}
	set i 0

    foreach byte $byte_list {
        if {$byte >= 0xAFAFAFA0 && $byte <= 0xAFAFAFBF} {
            # Escape using 2-byte format: 0xAE <byte & 0x7F>
            lappend encoded_list 0xAFAFAFAE
            lappend encoded_list [expr {0xAFAFAF00 | ($byte & 0x7F)}]
        } else {
            # Normal byte
            lappend encoded_list [expr {0xAFAFAF00 | $byte}]
        }
    }
    return $encoded_list
}

proc decode_sdc600_bytes {raw_list} {
    set decoded_list {}
    set i 0

    while {$i < [llength $raw_list]} {
        set b [lindex $raw_list $i]

        if {$b == 0xAE && ($i + 1) < [llength $raw_list]} {
            set next1 [lindex $raw_list [expr {$i + 1}]]
            set decoded_byte [expr {$next1 | 0x80}]
            lappend decoded_list $decoded_byte
            incr i 2
        } else {
            lappend decoded_list $b
            incr i
        }
    }

    return $decoded_list
}

proc sdc600_read_decoded {target_decoded_size} {
    set base_addr     0x20000
    set dr_addr       0xD30
    set dr_sr_addr    0xD3C
    set addr          [expr {$base_addr + $dr_addr}]
    set raw_bytes     {}
    set decoded_bytes {}

    echo "Starting read to get $target_decoded_size decoded bytes..."

    while {[llength $decoded_bytes] < $target_decoded_size} {
        # Wait until data is ready
        set status [m52.dap apreg $base_addr $dr_sr_addr]
        if {[expr {($status & 0x00010000) != 0}]} {
            set word [m52.dap apreg $base_addr $dr_addr]
            set lsb [expr {$word & 0xFF}]
            lappend raw_bytes $lsb
          #  puts "Raw byte: [format 0x%02X $lsb]"

            # Decode logic inline
            set len [llength $raw_bytes]
            if {$len >= 2 && [lindex $raw_bytes [expr {$len - 2}]] == 0xAE} {
                # Escape detected
                set escaped [lindex $raw_bytes [expr {$len - 1}]]
                set decoded_byte [expr {$escaped | 0x80}]
                lappend decoded_bytes $decoded_byte

                # Remove last 2 from raw list
                set raw_bytes [lrange $raw_bytes 0 [expr {$len - 3}]]
            } elseif {[lindex $raw_bytes end] != 0xAE} {
                # Normal byte
                lappend decoded_bytes [lindex $raw_bytes end]
                set raw_bytes [lrange $raw_bytes 0 [expr {[llength $raw_bytes] - 2}]]
            }
        }
        sleep 2
    }

    echo "Decoded complete: [llength $decoded_bytes] bytes"
    return $decoded_bytes
}

proc sdc600_write {data_list} {
    set base_addr 0x20000
    set dr_addr   0xd30
    set dr_sr_addr 0xd3c
    set addr [expr {$base_addr + $dr_addr}]
    set i 0

    echo "Start writing [llength $data_list] encoded words to device"

    while {$i < [llength $data_list]} {
        # Check if ready (bit 16 == 0)
        set status [m52.dap apreg $base_addr $dr_sr_addr]

        if {[expr {($status & 0x00010000) == 0x0}]
		    && [expr {($status & 0x00000001) == 0x1}]} {
            # Get current word
            set word [lindex $data_list $i]
            
            # Write word
            m52.dap apreg $base_addr $dr_addr $word
			set status [m52.dap apreg $base_addr $dr_sr_addr]

            # Debug output
            #puts "Wrote [format 0x%08X $word] to [format 0x%08X $addr], status is [format 0x%08X $status], i is [format %d $i]"
            echo "sending data to device, i is [format %d $i]"
            # Move to next word
            incr i

            # Wait 5ms (OpenOCD `sleep` is in ms)
            sleep 2
        } else {
            # Optional short wait when not ready
            sleep 2
        }
    }

    echo "Done writing all [llength $data_list] encoded words."
}

proc sdc600_read {size} {
    set base_addr 0x20000
    set dr_addr   0xd30
    set dr_sr_addr 0xd3c
    set addr [expr {$base_addr + $dr_addr}]
    set i 0
    set data_list {}

    echo "Starting to read $size words from 0x[format %08X $addr]"

    while {$i < $size} {
        # Check ready status (bit 16 == 1)
        set status [m52.dap apreg $base_addr $dr_sr_addr]

        if {[expr {($status & 0x00010000) != 0}]} {
            set data [m52.dap apreg $base_addr $dr_addr]
            echo "Read $i: [format 0x%08X $data]"
            lappend data_list $data
            incr i
        }

        # Small delay to avoid hammering the bus
        sleep 2
    }

    echo "Read complete: $i words collected"
    return $data_list
}

proc sdc600_send_cmd_scuk_id {} {
    set data_r_len 16
    set cmd_scuk_list {0xafafaf00 0xafafaf00 0xafafaf01 0xafafaf10}
	sdc600_write $cmd_scuk_list
	sleep 2
	
	#read the comand status to check if the command send successfully or not
	set data_r [sdc600_read_decoded $data_r_len]
	
	# Check the third byte (index 2),0x03: command fail, 0x00: command success,
    if {[lindex $data_r 2] == 0x03} {
        echo "ERROR:  invalid command to get SCUK ID!"
    } else {
        echo "SUCCESS: get SCUK ID successfully, the SCUK ID is "
          for {set i 7} {$i < $data_r_len} {incr i} {
            set val [lindex $data_r $i]
            echo [format " 0x%02X" $val]
          }
    }
}

proc sdc600_send_cmd_ccuk_id {} {
    set data_r_len 16
    set cmd_scuk_list {0xafafaf00 0xafafaf00 0xafafaf02 0xafafaf10}
	sdc600_write $cmd_scuk_list
	sleep 2
	
	#read the comand status to check if the command send successfully or not
	set data_r [sdc600_read_decoded $data_r_len]
	
	# Check the third byte (index 2),0x03: command fail, 0x00: command success,
    if {[lindex $data_r 2] == 0x03} {
        echo "ERROR:  invalid command to get SCUK ID!"
    } else {
        echo "SUCCESS: get CCUK ID successfully, the CCUK ID is "
          for {set i 7} {$i < $data_r_len} {incr i} {
            set val [lindex $data_r $i]
            echo [format " 0x%02X" $val]
          }
    }
}


proc sdc600_help {} {
    echo "sdc600_send_cmd_scuk_id: send command to get sdc600_send_cmd_scuk_id"
    echo "sdc600_send_cmd_ccuk_id: send command to get sdc600_send_cmd_ccuk_id"
}