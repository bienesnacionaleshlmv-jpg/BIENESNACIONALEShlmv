"""Importador Excel XLSX (OOXML), sin paquetes externos.
Reconoce prefichas de Bienes Nacionales y hojas tabulares similares.
El numero SIAFI nunca se reemplaza por un valor inventado.
"""
import hashlib
import io
import json
import re
import unicodedata
import zipfile
from xml.etree import ElementTree as ET

S = '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}'
R = '{http://schemas.openxmlformats.org/officeDocument/2006/relationships}'
P = '{http://schemas.openxmlformats.org/package/2006/relationships}'


def clean(value):
    if value is None:return ''
    return re.sub(r'\s+',' ',str(value)).strip()


def norm(value):
    return ''.join(c for c in unicodedata.normalize('NFD',clean(value).casefold()) if unicodedata.category(c) != 'Mn')


def column_index(ref):
    letters = re.match(r'[A-Za-z]+', ref or '')
    if not letters:return None
    idx = 0
    for c in letters.group().upper():idx = idx * 26 + ord(c) - 64
    return idx - 1


def _xml(z, path):
    with z.open(path) as f:return ET.fromstring(f.read())


def parse_sheets(blob):
    if not blob.startswith(b'PK'):
        raise ValueError('Selecciona un archivo Excel .xlsx válido, no XLS antiguo ni CSV.')
    try:z=zipfile.ZipFile(io.BytesIO(blob))
    except (zipfile.BadZipFile,ValueError):raise ValueError('Excel dañado o archivo incompatible.')
    with z:
        listing=z.infolist()
        if len(listing)>3500 or sum(x.file_size for x in listing)>80*1024*1024:
            raise ValueError('Excel demasiado grande o comprimido de manera sospechosa.')
        names=set(z.namelist())
        if 'xl/workbook.xml' not in names or 'xl/_rels/workbook.xml.rels' not in names:
            raise ValueError('Excel incompatible: faltan hojas del libro.')
        shared=[]
        if 'xl/sharedStrings.xml' in names:
            root=_xml(z,'xl/sharedStrings.xml')
            for si in root.findall(S+'si'):
                shared.append(''.join(t.text or '' for t in si.iter(S+'t')))
        rels={a.get('Id'):a.get('Target') for a in _xml(z,'xl/_rels/workbook.xml.rels').findall(P+'Relationship')}
        wb=_xml(z,'xl/workbook.xml')
        sheets=[]
        for ix,sh in enumerate(wb.findall(S+'sheets/'+S+'sheet')):
            target=rels.get(sh.get(R+'id'),'')
            if not target:continue
            # OOXML relative paths are rooted under xl/. Resolve only inside xl/worksheets.
            if target.startswith('/'):file=target.lstrip('/')
            elif target.startswith('xl/'):file=target
            else:
                import posixpath
                file=posixpath.normpath(posixpath.join('xl',target))
            if not file.startswith('xl/worksheets/') or file not in names:continue
            root=_xml(z,file)
            rows=[]
            for row_el in root.findall('.//'+S+'sheetData/'+S+'row'):
                row_num=int(row_el.get('r') or len(rows)+1)
                if row_num>30000:raise ValueError('La hoja contiene demasiadas filas.')
                values={}
                for c in row_el.findall(S+'c'):
                    j=column_index(c.get('r',''))
                    if j is None or j>200:continue
                    typ=c.get('t')
                    if typ=='inlineStr':
                        v=''.join(t.text or '' for t in c.iter(S+'t'))
                    else:
                        t=c.find(S+'v');v=t.text if t is not None and t.text is not None else ''
                        if typ=='s' and v!='':
                            k=int(v)
                            v=shared[k] if 0<=k<len(shared) else ''
                    values[j]=clean(v)
                rows.append((row_num,values))
            sheets.append({'name':clean(sh.get('name')),'index':ix,'rows':rows})
        return sheets


def pick_heading(headers, options):
    for c,v in headers.items():
        title=norm(v)
        if any(opt in title for opt in options):return c
    return None


def parse_workbook(blob):
    sheets=parse_sheets(blob)
    assets=[]; ignored=[]
    for sh in sheets:
        rows=sh['rows'];name=sh['name']
        header=None
        for i,values in rows[:40]:
            ci=pick_heading(values,('inventario','siafi','codigo del bien'))
            cd=pick_heading(values,('descripcion','nombre del bien','detalle del bien'))
            if ci is not None and cd is not None and ci!=cd:
                header=(i,values,ci,cd);break
        if header is None:
            ignored.append({'hoja':name,'motivo':'Sin encabezados de inventario y descripción'});continue
        hdrrow,hdr,ci,cd=header
        bcol=pick_heading(hdr,('marca',))
        modelcol=pick_heading(hdr,('modelo',))
        serialcol=pick_heading(hdr,('serie',))
        colorcol=pick_heading(hdr,('color',))
        statecol=pick_heading(hdr,('estado',))
        fichecol=pick_heading(hdr,('numero de ficha','no de ficha','ficha'))
        pricecol=pick_heading(hdr,('precio','valor','costo'))
        # Preficha: 'ESTADO DEL BIEN' y 'NUMERO DE FICHA' están sobre los encabezados.
        if statecol is None and any(norm(v).startswith('pre ficha') for n,r in rows[:6] for v in r.values()):
            statecol=12
        if fichecol is None and statecol==12:fichecol=13
        def value_at(row,index):return clean(row.get(index,'')) if index is not None else ''
        prefarea='';responsable=''
        for no,values in rows[:min(15,len(rows))]:
            for col,val in values.items():
                h=norm(val)
                if ('departamento/oficina' in h or 'institucion:' in h) and not prefarea:
                    candidates=[value_at(values,j) for j in (col+2,col+1)]
                    prefarea=next((x for x in candidates if x and 'institucion' not in norm(x)), '')
                if 'nombre de responsable' in h:
                    candidates=[value_at(values,j) for j in (col+2,col+1,col+3)]
                    responsable=next((x for x in candidates if x and 'fecha:' not in norm(x)), '')
        if not prefarea:
            # Plantillas con C8 para ubicación, C7 para instituciones.
            for no,values in rows[:10]:
                if no==8 and value_at(values,2):prefarea=value_at(values,2)
                if no==7 and not prefarea and value_at(values,2):prefarea=value_at(values,2)
        area=prefarea or (name if not re.match('^hoja\\d*',norm(name)) else 'Área por verificar')
        count=0
        for no,values in rows:
            if no<=hdrrow:continue
            d=value_at(values,cd);num=value_at(values,ci)
            if not d or norm(d) in ('descripcion del bien','datos del bien'):continue
            # Solo filas de bienes: ordinal numérico en primera columna en formato preficha,
            # o número o descripción presente cuando se trata de tabla normal.
            ordinal=value_at(values,0)
            if ci==1 and not re.fullmatch(r'\d+(?:\.0+)?',ordinal):continue
            if not num and ci!=1:continue
            if len(d)>1000:continue
            nclean=re.sub(r'\.0+$','',num)
            valid=bool(re.fullmatch(r'[0-9][0-9A-Za-z._/-]*',nclean)) and norm(nclean) not in ('0','000')
            # Para faltantes se usa un ID interno estable (NO es un identificador SIAFI).
            uid='PEND-'+hashlib.sha256(f'{norm(area)}|{sh["index"]}|{no}|{norm(d)}'.encode()).hexdigest()[:12].upper()
            number=nclean if valid else uid
            state=value_at(values,statecol)
            fiche=value_at(values,fichecol)
            assets.append({
              'hoja':name, 'fila':no, 'area':area,'responsable':responsable,
              'numeroInventario':number,'numeroOriginal':num, 'pendienteNumero':not valid,
              'descripcion':d, 'marca':value_at(values,bcol),'modelo':value_at(values,modelcol),
              'numeroSerie':value_at(values,serialcol), 'color':value_at(values,colorcol),
              'estadoOriginal':state, 'estadoBueno':norm(state) in ('bueno','b','buen estado','excelente'),
              'numeroFicha':fiche, 'precio':value_at(values,pricecol),
            })
            count+=1
        if count==0:ignored.append({'hoja':name,'motivo':'Plantilla sin bienes completos'})
    if not assets:raise ValueError('No se encontraron bienes. Verifica los encabezados y que el Excel tenga descripciones.')
    if len(assets)>12000:raise ValueError('Demasiados bienes en un solo archivo (máximo 12,000).')
    return {'bienes':assets,'hojasIgnoradas':ignored}
