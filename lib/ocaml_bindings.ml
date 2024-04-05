(* Wrap a simple function. *)

let hello_world () = "Hello, world!"

let () = Callback.register "hello_world" hello_world
let main () =
  Cap.main (fun (caps : Cap.all_caps) ->
      let argv = CapSys.argv caps#argv in
    let exit_code = CLI.main (caps :> CLI.caps) argv in
    (* remove? or make debug-only? or use Logs.info? *)
    if not (Exit_code.Equal.ok exit_code) then
    Printf.eprintf "Error: %s\nExiting with error status %i: %s\n%!"
        exit_code.description exit_code.code
        (String.concat " " (Array.to_list argv));
    CapStdlib.exit caps#exit exit_code.code)
