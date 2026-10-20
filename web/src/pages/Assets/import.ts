export const maxAssetImportBytes = 1 << 20;
export interface AssetImportRow {row:number;kind:string;address:string;businessGroup:string;owner:string;name?:string;reason?:string}
export interface AssetImportPreview {previewId?:string;expiresAt?:string;total:number;valid:number;invalid:number;rows:AssetImportRow[]}
export function assertImportFile(file:{size:number}) {
  if(file.size===0||file.size>maxAssetImportBytes)throw new Error('请选择不超过 1 MiB 的 UTF-8 CSV 文件');
}
export function canConfirmImport(preview:AssetImportPreview|null,accepted:boolean,busy:boolean,now=Date.now()) {
  return !!preview?.previewId&&preview.total>0&&preview.invalid===0&&preview.valid===preview.total&&accepted&&!busy&&Date.parse(preview.expiresAt??'')>now;
}
