##################################################
# Open this with IDA's File -> Script File.
# Then select a mpb file exported by CakeTool.
##################################################

class MyForm(Form):
    def __init__(self):
        self.invert = False
        Form.__init__(self, r"""STARTITEM {id:rNormal}
BUTTON YES* Process
BUTTON NO Abort

Mpb Importer
<#Select MPB file#MPB file:{iFileOpen}>
""", {
            'iFileOpen': Form.FileInput(open=True),
            'cGroup1': Form.ChkGroupControl(("rNormal", "rError", "rWarnings")),
        })


def ida_main():
    # Create form
    global f
    f = MyForm()

    # Compile (in order to populate the controls)
    f.Compile()

    f.iFileOpen.value = "*.*"
    # Execute the form
    ok = f.Execute()

    if ok == 1:
        num_lines = sum(1 for _ in open(f.iFileOpen.value))

        with open(f.iFileOpen.value) as diary_file:
            n = 1
            for line in diary_file:
                spl = line.split('\t')
        
                ida_name.set_name(int(spl[0], 16), spl[1], idaapi.SN_FORCE)
        
                if n % 100 == 0:
                    print(str((n / num_lines * 100)) + " " + spl[1])
            
                n += 1

    # Dispose the form
    f.Free()
    
ida_main()
