"""Lector del reporte SIAFI 'RECIBO DE ASIGNACION DE BIENES' (PDF de texto).

Lee posiciones del texto vectorial, NO OCR. Mantiene el N.º ficha y el
identificador de inventario completo. Deja inconclusos y contradicciones
para revisión; no inventa números ni ubicaciones.
Requiere PyMuPDF: pip install pymupdf
"""
import io
import re
import unicodedata
from collections import Counter


class PDFImportError(ValueError):
    pass


def compact(value):
    return ' '.join(str(value or '').split()).strip()


def norm(value):
    d = unicodedata.normalize('NFD', compact(value).casefold())
    return ''.join(x for x in d if unicodedata.category(x) != 'Mn')


def _lines(page):
    """Agrupar las palabras por coordenada Y; evitar lectura columnar a ciegas."""
    words = sorted(page.get_text('words', sort=False), key=lambda w: (w[1], w[0]))
    lines = []
    for w in words:
        y = w[1]
        # Las palabras de una línea del reporte difieren menos de ~2 pt en y.
        closest = next((ln for ln in reversed(lines[-5:]) if abs(ln['y'] - y) < 2.6), None)
        if closest is None:
            closest = {'y':y, 'words': []}
            lines.append(closest)
        closest['words'].append((w[0], w[2], str(w[4])))
    for ln in lines:
        ln['words'].sort(key=lambda w: w[0])
        ln['text'] = compact(' '.join(w[2] for w in ln['words']))
    return sorted(lines, key=lambda ln: ln['y'])


def _segment(line, lower, upper):
    return compact(' '.join(word for x, x1, word in line['words'] if lower <= x < upper))


def _get_location(lines, idx):
    """El valor de Oficina aparece después de la cabecera 'Oficina' (x~680)."""
    start = lines[idx]['y']
    sub = [x for x in lines[idx+1:] if 0 < x['y']-start < 43]
    if any('Oficina' in ln['text'] for ln in sub):
        row = next((j for j,l in enumerate(sub) if 'Oficina' in l['text'] and 'Piso' in l['text']),None)
        if row is not None:
            h=sub[row]['y']; name=[]
            for ln in sub[row+1:]:
                if ln['y']-h > 26 or 'Nro Ficha' in ln['text']:break
                val=_segment(ln,617,751)
                if val and not re.search(r'^(?:Teléfono|Oficina|Piso)$',val,re.I):name.append(val)
            if name: return compact(' '.join(name))
    return ''


def _model(desc):
    if re.search(r'\bSIN MODELO\b',desc,re.I):return ''
    match=re.search(r'\bMODELO\s+(.+?)(?:,|;|\.\s|\bESTRUCTURA\b|\bCAPACIDAD\b|\bTIPO\b|$)',desc,re.I)
    return compact(match.group(1))[:120] if match else ''


def _parse_price(txt):
    try:return round(float(txt.replace(',','')),2)
    except:return None


def _parse_row(lines, start, end, context, page):
    rows = lines[start:end]
    first=rows[0]
    ficha=_segment(first,0,53)
    item=_segment(first,53,102)
    desc=compact(' '.join(_segment(l,102,268) for l in rows))
    brand=compact(' '.join(_segment(l,268,342) for l in rows))
    serie=compact(' '.join(_segment(l,342,468) for l in rows))
    prev=compact(' '.join(_segment(l,468,539) for l in rows))
    color=compact(' '.join(_segment(l,539,604) for l in rows))
    amount=compact(' '.join(_segment(l,604,655) for l in rows))
    siafi=compact(''.join(_segment(l,655,790).replace(' ','') for l in rows))
    # En el PDF SIAFI, el número final se imprime en la línea inmediatamente inferior.
    # Validación antes de importar, cualquier campo ilegible se anota como anomalía.
    issues=[]
    if not re.fullmatch(r'\d{6,8}',ficha):issues.append('Número de ficha no reconocido')
    if not desc:issues.append('Falta descripción')
    if not re.fullmatch(r'\d{8}-\d{10}-\d{8}-\d{6}',siafi):issues.append('SIAFI incompleto/ilegible')
    if not amount or _parse_price(amount) is None:issues.append('Costo no legible')
    if not context.get('oficina'):issues.append('Oficina no identificada')
    return {'numeroFicha':ficha,'codigoItemSiafi':item,'descripcion':desc,'modelo':_model(desc),'marca':brand,
      'numeroSerie':serie,'numeroInventarioAnterior':prev,'color':color,'precio':_parse_price(amount),
      'numeroInventario':siafi,'oficinaOriginal':context.get('oficina',''),
      'departamentoOriginal':context.get('departamento',''),'institucionOriginal':context.get('institucion',''),
      'responsable':context.get('responsable',''),'identidadResponsable':context.get('identidad',''),
      'paginaPDF':page,'incidencias':issues}


def parse_siafi_pdf(data):
    if not isinstance(data,(bytes,bytearray)) or not data.startswith(b'%PDF-'):
        raise PDFImportError('El archivo no es un PDF válido.')
    if len(data)>30*1024*1024:raise PDFImportError('PDF demasiado grande (máximo 30 MB).')
    try:
        import fitz
    except ImportError as exc:
        raise PDFImportError('Falta PyMuPDF. Instálalo con: py -m pip install pymupdf') from exc
    try:
        doc=fitz.open(stream=io.BytesIO(data),filetype='pdf')
    except Exception as exc:raise PDFImportError('No se pudo abrir el PDF.') from exc
    if doc.is_encrypted or len(doc)>250:
        raise PDFImportError('PDF protegido o demasiado extenso (máximo 250 páginas).')
    context={'oficina':'','departamento':'','institucion':'','responsable':'','identidad':''}
    records=[];warnings=[]
    for pno,page in enumerate(doc,1):
        lines=_lines(page)
        page_text='\n'.join(x['text'] for x in lines)
        if 'RECIBO DE ASIGNACION DE BIENES' not in page_text or 'Nro' not in page_text:
            warnings.append(f'Página {pno}: no se reconoce el formato del reporte SIAFI.')
            continue
        # Empezar nueva institución cada página, conservando la oficina hasta encontrar otra.
        if 'GERENCIA ADMINSTRATIVA DEPARTAMENTO DE SANTA' in page_text or 'DIRECCIÓN DEPARTAMENTAL DE SANTA' in page_text:
            context['institucion']='DIRECCIÓN DEPARTAMENTAL DE SANTA BÁRBARA'
        elif 'HOSPITAL LEONARDO MARTINEZ' in page_text:
            context['institucion']='HOSPITAL LEONARDO MARTÍNEZ VALENZUELA'
        for l in lines:
            if 'TID' in l['text'] and l['words'] and l['words'][0][0] < 31:
                name=_segment(l,0,211)
                if name and not name.startswith('Nombre'):
                    context['responsable']=name
                    ident=re.search(r'\b\d{13}\b',l['text'])
                    context['identidad']=ident.group() if ident else ''
                    break
        starts=[];contexts={}
        for i,ln in enumerate(lines):
            text=ln['text']
            if 'Depto.' in text and ('SALA DE OPERACIONES' in text or 'MATERNIDAD' in text or 'OTRAS DEPENDENCIAS' in text or 'ENFERMERÍA' in text):
                context['departamento']=_segment(ln,169,385)
            if text.startswith('UBICACION BIENES'):
                new_location=_get_location(lines,i)
                if new_location:context['oficina']=new_location
            # Detección exacta de ficha de 7 dígitos, ubicada en la primera columna.
            words=ln['words']
            if words and words[0][0]<32 and re.fullmatch(r'\d{7}',words[0][2]) and len(words)>2:
                starts.append(i);contexts[i]=dict(context)
        for k,idx in enumerate(starts):
            stop=starts[k+1] if k+1<len(starts) else len(lines)
            # La sección de totales/firmas posterior no pertenece al último bien.
            for j in range(idx+1,stop):
                if any(phrase in lines[j]['text'] for phrase in ('Cantidad por Ubicación', 'Cantidad por Responsable','Los Bienes Descritos', 'ESTRUCTURA ORGANIZACIONAL', 'UBICACION BIENES')):
                    stop=j;break
            rec=_parse_row(lines,idx,stop,contexts[idx],pno)
            records.append(rec)
    doc.close()
    if not records:raise PDFImportError('No se encontraron bienes. Este formato requiere texto seleccionable, no imágenes escaneadas.')
    keys=[r['numeroInventario'] for r in records if not r['incidencias'] or 'SIAFI incompleto/ilegible' not in r['incidencias']]
    dup={k:c for k,c in Counter(keys).items() if c>1}
    for r in records:
        if r['numeroInventario'] in dup:
            r['incidencias'].append('Número SIAFI repetido en el PDF')
        if 'HOSPITAL LEONARDO' not in r['institucionOriginal']:
            r['incidencias'].append('Entidad distinta al HLMV; requiere validación antes de importar')
    return {'registros':records,'paginas':pno, 'incidencias':sum(bool(r['incidencias']) for r in records),
        'duplicadosSiafi':dup, 'ubicaciones':dict(Counter(r['oficinaOriginal'] or 'SIN UBICACIÓN' for r in records)),
        'fueraHospital':sum('HOSPITAL LEONARDO' not in r['institucionOriginal'] for r in records),
        'avisos':warnings}
