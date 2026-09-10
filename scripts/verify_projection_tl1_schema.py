"""Compare the pinned schema interpreter with independent Ajv 8.17.1.

Ajv must already be installed under the explicitly supplied temporary directory.
This script never installs dependencies or fetches a schema.
"""
import argparse
import json
import subprocess
import tempfile
from pathlib import Path
from scripts.projection_tl1_support import offer, DID, HEX
from scout_projection_tclk import structural, SCHEMA_PATH


def corpus():
    frames = [offer(), dict(type='accept', **{'from':DID},ref=HEX,contract=HEX,statement=HEX,nonce='12345678'),
              dict(type='lock', **{'from':DID},contract=HEX,rail='memory',ref='rail-1'),
              dict(type='reveal', **{'from':DID},contract=HEX,secret=HEX),
              dict(type='refund', **{'from':DID},contract=HEX), dict(type='cancel', **{'from':DID},contract=HEX),
              dict(type='receipt', **{'from':DID},contract=HEX,outcome='claimed'),
              dict(type='heartbeat', **{'from':DID},contract=HEX,nonce='12345678')]
    values = [None,False,True,0,1,1.0,-1,1.5,'',' ','x',HEX,HEX+'\n',HEX+'\r','12345678','12345678\n',[],['claimed'],{},
              {'proto':'a','id':'x'},{'nonce':'0x'+'1'*66,'s':'0x11'}]
    cases = []
    for frame in frames:
        cases.append(frame)
        for key in sorted(set(frame) | {'offer_id','unknown','paymentKey','job','presig','note','ref','contract'}):
            missing=dict(frame);missing.pop(key,None);cases.append(missing)
            for value in values:
                changed=dict(frame);changed[key]=value;cases.append(changed)
    return [dict(frame=frame,producer_valid=structural('tclk1 '+json.dumps(frame))[1]==0) for frame in cases]


def run(ajv_root, output):
    package=json.loads((ajv_root/'node_modules/ajv/package.json').read_text())
    assert package['version']=='8.17.1'
    cases=corpus()
    with tempfile.TemporaryDirectory(prefix='tl1-schema-parity-',dir='/private/tmp') as directory:
        data=Path(directory)/'cases.json';data.write_text(json.dumps(cases))
        script='''
const fs=require('fs'), path=require('path');
const Ajv=require(path.join(process.argv[2],'node_modules/ajv/dist/2020'));
const schema=JSON.parse(fs.readFileSync(process.argv[3],'utf8'));
const validate=new Ajv({strict:false,allErrors:true,validateFormats:false}).compile(schema);
const cases=JSON.parse(fs.readFileSync(process.argv[4],'utf8'));
const mismatches=[];
cases.forEach((c,index)=>{const valid=validate(c.frame);if(valid!==c.producer_valid)mismatches.push({index,valid,producer_valid:c.producer_valid,errors:validate.errors});});
console.log(JSON.stringify({validator:'ajv/8.17.1 Draft 2020-12',cases:cases.length,mismatch_count:mismatches.length,mismatches}));
'''
        result=subprocess.run(['node','-',str(ajv_root),str(SCHEMA_PATH),str(data)],input=script,text=True,capture_output=True,check=True)
    report=json.loads(result.stdout)
    output.write_text(json.dumps(report,indent=2)+'\n')
    assert report['mismatch_count']==0
    print(json.dumps(report))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--ajv-root',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();run(args.ajv_root.resolve(),args.output.resolve())
