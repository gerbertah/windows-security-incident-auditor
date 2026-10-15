#requires -Version 5.1
<#
.SYNOPSIS
 Auditoria de seguridad de solo lectura para Windows 10/11 y Windows Server 2019/2022/2025.
.DESCRIPTION
 Consulta eventos locales Security y genera CSV, HTML y notas de cobertura.
 Ejecutar elevado. No cambia politicas ni limpia registros.
.EXAMPLE
 .\Audit-WindowsSecurity.ps1
.EXAMPLE
 .\Audit-WindowsSecurity.ps1 -Dias 7 -Modo Todo -MaximoPorEvento 5000 -SinPreguntas
#>
[CmdletBinding()]
param(
    [ValidateRange(0,3650)][int]$Dias = 0,
    [string]$Salida = '',
    [ValidateSet('Todo','Accesos','Cuentas')][string]$Modo = 'Todo',
    [ValidateRange(0,1000000)][int]$MaximoPorEvento = 0,
    [switch]$SinPreguntas
)
$ErrorActionPreference = 'Stop'

function Aviso([string]$Mensaje) { Write-Host "[INFO] $Mensaje" -ForegroundColor Cyan }
function Preguntar-Entero([string]$Texto,[int]$Defecto,[int]$Min,[int]$Max) {
    while ($true) {
        $Respuesta = Read-Host "$Texto [$Defecto]"
        if ([string]::IsNullOrWhiteSpace($Respuesta)) { return $Defecto }
        $ValorNumerico = 0
        if ([int]::TryParse($Respuesta, [ref]$ValorNumerico) -and $ValorNumerico -ge $Min -and $ValorNumerico -le $Max) { return $ValorNumerico }
        Write-Host "Ingrese un entero entre $Min y $Max." -ForegroundColor Yellow
    }
}
function Progreso([int]$Porcentaje,[string]$Estado) {
    Write-Progress -Id 1 -Activity 'Auditoria de seguridad Windows' -Status $Estado -PercentComplete ([Math]::Max(0,[Math]::Min(100,$Porcentaje)))
}
function Campo($Datos,[string]$Nombre) {
    if ($Datos.ContainsKey($Nombre)) { return [string]$Datos[$Nombre] }
    return ''
}
function Cuenta([string]$Dominio,[string]$Nombre) {
    if ([string]::IsNullOrWhiteSpace($Nombre)) { return '' }
    if ([string]::IsNullOrWhiteSpace($Dominio) -or $Dominio -eq '-') { return $Nombre }
    return "$Dominio\$Nombre"
}
function Convertir-Evento($Evento) {
    [xml]$Xml = $Evento.ToXml()
    $D = @{}
    foreach ($N in $Xml.Event.EventData.Data) {
        if ($N.Name) { $D[[string]$N.Name] = [string]$N.'#text' }
    }
    $Acciones = @{
        4624='Inicio exitoso'; 4625='Inicio fallido'; 4672='Privilegios especiales en inicio'
        4720='Cuenta creada'; 4722='Cuenta habilitada'; 4723='Cambio de contrasena solicitado'
        4724='Contrasena restablecida'; 4725='Cuenta deshabilitada'; 4726='Cuenta eliminada'
        4728='Agregado a grupo global'; 4729='Retirado de grupo global'
        4732='Agregado a grupo local'; 4733='Retirado de grupo local'
        4738='Cuenta modificada'; 4740='Cuenta bloqueada'
        4756='Agregado a grupo universal'; 4757='Retirado de grupo universal'
        1102='Registro Security borrado'
    }
    $EsGrupo = $Evento.Id -in @(4728,4729,4732,4733,4756,4757)
    $Afectado = Cuenta (Campo $D 'TargetDomainName') (Campo $D 'TargetUserName')
    $Grupo = ''
    $MiembroSid = ''
    if ($EsGrupo) {
        $Grupo = $Afectado
        $MiembroSid = Campo $D 'MemberSid'
        $Afectado = Campo $D 'MemberName'
        if (-not $Afectado -or $Afectado -eq '-') { $Afectado = $MiembroSid }
    }
    $Responsable = Cuenta (Campo $D 'SubjectDomainName') (Campo $D 'SubjectUserName')
    if ($Evento.Id -eq 1102) { $Responsable = Cuenta (Campo $D 'SubjectDomainName') (Campo $D 'SubjectUserName') }
    $Ip = Campo $D 'IpAddress'
    if ($Ip -eq '-') { $Ip = '' }
    [pscustomobject][ordered]@{
        FechaHora       = $Evento.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        Equipo          = $Evento.MachineName
        EventoID        = $Evento.Id
        Accion          = $Acciones[[int]$Evento.Id]
        UsuarioAfectado = $Afectado
        Responsable     = $Responsable
        Grupo           = $Grupo
        GrupoSID        = if ($EsGrupo) { Campo $D 'TargetSid' } else { '' }
        MiembroSID      = $MiembroSid
        IPOrigen        = $Ip
        EquipoOrigen    = Campo $D 'WorkstationName'
        TipoInicio      = Campo $D 'LogonType'
        Estado          = Campo $D 'Status'
        SubEstado       = Campo $D 'SubStatus'
        RegistroID      = $Evento.RecordId
    }
}
function Exportar-CsvSeguro($Datos,[string]$Ruta,[string[]]$Columnas) {
    $Filas = @($Datos)
    if ($Filas.Count -gt 0) {
        $Filas | Export-Csv -LiteralPath $Ruta -NoTypeInformation -Delimiter ';' -Encoding UTF8
    } else {
        $Encabezado = ($Columnas | ForEach-Object { '"' + ($_ -replace '"','""') + '"' }) -join ';'
        [System.IO.File]::WriteAllText($Ruta, $Encabezado + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($true)))
    }
}
function HtmlTabla($Datos,[string]$Vacio = 'Sin registros') {
    $Filas = @($Datos)
    if ($Filas.Count -eq 0) { return "<p class='vacio'>$Vacio</p>" }
    return ($Filas | ConvertTo-Html -Fragment | Out-String)
}
function HtmlTexto($Texto) { return [System.Net.WebUtility]::HtmlEncode([string]$Texto) }

$Identidad = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($Identidad)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Ejecute PowerShell como administrador.'
}
$Sistema = Get-CimInstance Win32_OperatingSystem
$Maquina = Get-CimInstance Win32_ComputerSystem
$EsDC = [int]$Maquina.DomainRole -ge 4
$Rol = if ($EsDC) { 'Controlador de dominio' } elseif ($Maquina.PartOfDomain) { 'Equipo miembro de dominio' } else { 'Grupo de trabajo / Independiente' }
Write-Host "`n==== AUDITORIA DE SEGURIDAD WINDOWS ==== " -ForegroundColor Cyan
Write-Host "Equipo: $env:COMPUTERNAME | SO: $($Sistema.Caption) | Rol: $Rol"
Write-Host 'Modo de operacion: solo lectura de eventos y membresias.'
if ($Dias -eq 0) {
    if ($SinPreguntas) { $Dias = 30 }
    else {
        Write-Host "`nPeriodo: 1) 30 dias  2) 60 dias  3) 90 dias  4) Personalizado"
        $Eleccion = Preguntar-Entero 'Opcion' 1 1 4
        $Dias = switch ($Eleccion) { 1 {30} 2 {60} 3 {90} 4 {Preguntar-Entero 'Dias' 30 1 3650} }
    }
}
if (-not $SinPreguntas) {
    Write-Host "`nAlcance: 1) Completo  2) Accesos  3) Cuentas y grupos"
    $Eleccion = Preguntar-Entero 'Opcion' 1 1 3
    $Modo = @('Todo','Accesos','Cuentas')[$Eleccion - 1]
}
if (-not $Salida) {
    $Salida = Join-Path $env:ProgramData 'AuditoriaSeguridad'
    if (-not $SinPreguntas) {
        $Respuesta = Read-Host "Carpeta destino [$Salida]"
        if (-not [string]::IsNullOrWhiteSpace($Respuesta)) { $Salida = $Respuesta.Trim('"') }
    }
}
if ($MaximoPorEvento -eq 0 -and -not $SinPreguntas) {
    $MaximoPorEvento = Preguntar-Entero 'Maximo por ID (0 = sin limite)' 20000 0 1000000
}
if ($MaximoPorEvento -eq 0 -and $SinPreguntas) { Aviso 'Sin limite de registros por evento: la consulta puede ser extensa.' }
$Inicio = (Get-Date).AddDays(-$Dias)
$Carpeta = Join-Path $Salida ("{0}_{1}" -f $env:COMPUTERNAME,(Get-Date -Format 'yyyyMMdd_HHmmss'))
New-Item -ItemType Directory -Path $Carpeta -Force | Out-Null
$IdsAcceso = @(4624,4625,4672,4740)
$IdsCuenta = @(4720,4722,4723,4724,4725,4726,4728,4729,4732,4733,4738,4756,4757,1102)
$Ids = if ($Modo -eq 'Accesos') { $IdsAcceso } elseif ($Modo -eq 'Cuentas') { $IdsCuenta } else { @($IdsAcceso + $IdsCuenta) }
$Columnas = @('FechaHora','Equipo','EventoID','Accion','UsuarioAfectado','Responsable','Grupo','GrupoSID','MiembroSID','IPOrigen','EquipoOrigen','TipoInicio','Estado','SubEstado','RegistroID')
$Lista = New-Object 'System.Collections.Generic.List[object]'
$Avisos = New-Object 'System.Collections.Generic.List[string]'
$Limites = New-Object 'System.Collections.Generic.List[string]'
$Reloj = [Diagnostics.Stopwatch]::StartNew()
$Indice = 0
foreach ($Id in $Ids) {
    $Indice++
    $Base = [int](75 * ($Indice - 1) / $Ids.Count)
    Progreso $Base "Leyendo evento $Id ($Indice de $($Ids.Count))"
    Aviso "Evento $Id ($Indice/$($Ids.Count)); tiempo transcurrido: $([int]$Reloj.Elapsed.TotalSeconds)s"
    $Contador = 0
    try {
        $Parametros = @{FilterHashtable=@{LogName='Security'; Id=$Id; StartTime=$Inicio}; ErrorAction='Stop'}
        if ($MaximoPorEvento -gt 0) { $Parametros.MaxEvents = $MaximoPorEvento }
        Get-WinEvent @Parametros | ForEach-Object {
            $Registro = $_
            try {
                $Lista.Add((Convertir-Evento $Registro))
                $Contador++
                if (($Contador % 500) -eq 0) {
                    Aviso "Evento ${Id}: $Contador registros procesados"
                    $Fraccion = if ($MaximoPorEvento -gt 0) { [Math]::Min(1,$Contador / [double]$MaximoPorEvento) } else { 0 }
                    $Pct = [int][Math]::Min(75,($Base + (75.0 / $Ids.Count) * $Fraccion))
                    Progreso $Pct "Evento ${Id}: $Contador procesados"
                }
            } catch { $Avisos.Add("No se pudo interpretar RecordId $($Registro.RecordId), ID ${Id}: $($_.Exception.Message)") }
        }
        Aviso "Evento ${Id}: $Contador registros obtenidos"
        if ($MaximoPorEvento -gt 0 -and $Contador -ge $MaximoPorEvento) { $Limites.Add("Evento ${Id}: limite de $MaximoPorEvento alcanzado; datos parciales") }
    } catch {
        $ErrorTexto = $_.Exception.Message
        if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound' -or $ErrorTexto -match 'No events were found|No se encontraron eventos|No se han encontrado eventos') {
            Aviso "Evento ${Id}: sin coincidencias en el periodo"
        } else { $Avisos.Add("Error consultando evento ${Id}: $ErrorTexto"); Write-Warning "Evento ${Id}: $ErrorTexto" }
    }
}
Progreso 77 'Clasificando eventos y exportando CSV'
$Registros = @($Lista.ToArray() | Sort-Object FechaHora -Descending)
$Fallidos = @($Registros | Where-Object { $_.EventoID -eq 4625 })
# 2=consola, 3=acceso de red y 10=RDP; mantener todos para cobertura de IP
$Exitosos = @($Registros | Where-Object { $_.EventoID -eq 4624 -and $_.TipoInicio -in @('2','3','10') })
$CambiosCuentas = @($Registros | Where-Object { $_.EventoID -in @(4720,4722,4723,4724,4725,4726,4738,4740) })
$CambiosGrupos = @($Registros | Where-Object { $_.EventoID -in @(4728,4729,4732,4733,4756,4757) })
$Privilegios = @($Registros | Where-Object { $_.EventoID -eq 4672 })
$Borrados = @($Registros | Where-Object { $_.EventoID -eq 1102 })
$PorIp = @($Fallidos | Where-Object { $_.IPOrigen -and $_.IPOrigen -ne '-' } | Group-Object IPOrigen | Sort-Object Count -Descending | ForEach-Object { [pscustomobject]@{ IPOrigen=$_.Name; IntentosFallidos=$_.Count } })
Exportar-CsvSeguro $Registros (Join-Path $Carpeta 'Auditoria_Completa.csv') $Columnas
Exportar-CsvSeguro $Fallidos (Join-Path $Carpeta 'Intentos_Fallidos.csv') $Columnas
Exportar-CsvSeguro $Exitosos (Join-Path $Carpeta 'Inicios_Exitosos.csv') $Columnas
Exportar-CsvSeguro $CambiosCuentas (Join-Path $Carpeta 'Cambios_Cuentas.csv') $Columnas
Exportar-CsvSeguro $CambiosGrupos (Join-Path $Carpeta 'Cambios_Grupos.csv') $Columnas
Exportar-CsvSeguro $Privilegios (Join-Path $Carpeta 'Privilegios_Especiales.csv') $Columnas
Exportar-CsvSeguro $Borrados (Join-Path $Carpeta 'Borrados_Security.csv') $Columnas
Exportar-CsvSeguro $PorIp (Join-Path $Carpeta 'Fallidos_Por_IP.csv') @('IPOrigen','IntentosFallidos')
Progreso 88 'Enumerando membresias administrativas'
$Admins = @()
$ColsAdmin = @('Ambito','Grupo','Miembro','Tipo','SID','Origen')
if (-not $EsDC) {
    try {
        $GrupoLocal = Get-LocalGroup -SID 'S-1-5-32-544'
        $Admins = @(Get-LocalGroupMember -Group $GrupoLocal.Name | ForEach-Object {
            [pscustomobject]@{ Ambito='Local'; Grupo=$GrupoLocal.Name; Miembro=$_.Name; Tipo=$_.ObjectClass; SID=[string]$_.SID; Origen=[string]$_.PrincipalSource }
        })
    } catch { $Avisos.Add("Administradores locales: $($_.Exception.Message)") }
} elseif (Get-Module -ListAvailable -Name ActiveDirectory) {
    try {
        Import-Module ActiveDirectory
        $Dominio = Get-ADDomain
        $Grupos = @(@{Etiqueta='BUILTIN Administrators'; SID='S-1-5-32-544'},@{Etiqueta='Domain Admins'; SID="$($Dominio.DomainSID.Value)-512"})
        try {
            $Bosque = Get-ADForest
            $Raiz = Get-ADDomain -Identity $Bosque.RootDomain
            $Grupos += @{Etiqueta='Enterprise Admins';SID="$($Raiz.DomainSID.Value)-519"}
        } catch { $Avisos.Add("Enterprise Admins: $($_.Exception.Message)") }
        foreach ($G in $Grupos) {
            try {
                $GrupoAD = Get-ADGroup -Identity $G.SID
                foreach ($Miembro in @(Get-ADGroupMember -Identity $GrupoAD)) {
                    $Admins += [pscustomobject]@{ Ambito='Active Directory'; Grupo=$G.Etiqueta; Miembro=$Miembro.Name; Tipo=$Miembro.objectClass; SID=[string]$Miembro.SID; Origen=$Miembro.DistinguishedName }
                }
            } catch { $Avisos.Add("Grupo $($G.Etiqueta): $($_.Exception.Message)") }
        }
    } catch { $Avisos.Add("Error consultando Active Directory: $($_.Exception.Message)") }
} else { $Avisos.Add('Modulo ActiveDirectory ausente: no se consultaron membresias administrativas del dominio.') }
Exportar-CsvSeguro $Admins (Join-Path $Carpeta 'Administradores_Actuales.csv') $ColsAdmin
Progreso 95 'Generando panel HTML'
$TabAdmins = HtmlTabla @($Admins | Select-Object Ambito,Grupo,Miembro,Tipo,Origen)
$TabIp = HtmlTabla @($PorIp | Select-Object -First 10)
$TabFallidos = HtmlTabla @($Fallidos | Select-Object -Property FechaHora,UsuarioAfectado,IPOrigen,TipoInicio,Estado -First 50)
$TabExitosos = HtmlTabla @($Exitosos | Select-Object -Property FechaHora,UsuarioAfectado,IPOrigen,TipoInicio -First 50)
$TabCuentas = HtmlTabla @($CambiosCuentas | Select-Object -Property FechaHora,Accion,UsuarioAfectado,Responsable -First 100)
$TabGrupos = HtmlTabla @($CambiosGrupos | Select-Object -Property FechaHora,Accion,Grupo,UsuarioAfectado,Responsable -First 100)
$HostHtml = HtmlTexto $env:COMPUTERNAME
$SoHtml = HtmlTexto $Sistema.Caption
$RolHtml = HtmlTexto $Rol
$Reporte = Join-Path $Carpeta "Reporte_Seguridad_$env:COMPUTERNAME.html"
$Html = @"
<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Auditoria - $HostHtml</title><style>
body{background:#0b1120;color:#f1f5f9;font:14px Segoe UI,Arial,sans-serif;margin:25px}main{max-width:1300px;margin:auto}h1{color:#38bdf8}h2{color:#facc15;font-size:17px}section{background:#1e293b;padding:18px;margin:18px 0;border-radius:10px;overflow-x:auto}.stats{display:flex;gap:12px;flex-wrap:wrap}.stats div{background:#334155;padding:14px;border-radius:8px;min-width:140px}.stats b{display:block;font-size:24px}table{border-collapse:collapse;width:100%;font-size:12px}th,td{border-bottom:1px solid #475569;text-align:left;padding:8px;overflow-wrap:anywhere}th{color:#93c5fd}tr:nth-child(even){background:#283548}.vacio{color:#a7f3d0}
</style></head><body><main><h1>Auditoria de Seguridad Windows</h1>
<p><b>Equipo:</b> $HostHtml &nbsp; <b>SO:</b> $SoHtml &nbsp; <b>Rol:</b> $RolHtml</p>
<p><b>Periodo:</b> ultimos $Dias dias &nbsp; <b>Generado:</b> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') &nbsp; <b>Alcance:</b> $Modo</p>
<div class="stats"><div><b>$($Fallidos.Count)</b>Fallidos</div><div><b>$($Exitosos.Count)</b>Exitosos (2, 3, 10)</div><div><b>$($CambiosCuentas.Count)</b>Cambios cuentas</div><div><b>$($CambiosGrupos.Count)</b>Cambios grupos</div><div><b>$($Admins.Count)</b>Miembros admin listados</div></div>
<section><h2>Administradores actuales (membresia directa)</h2>$TabAdmins</section>
<section><h2>IP con mas intentos fallidos</h2>$TabIp</section>
<section><h2>Ultimos 50 accesos fallidos</h2>$TabFallidos</section>
<section><h2>Ultimos 50 accesos exitosos (tipos 2, 3 y 10)</h2>$TabExitosos</section>
<section><h2>Ultimos 100 eventos de cuentas</h2>$TabCuentas</section>
<section><h2>Ultimos 100 cambios en grupos</h2>$TabGrupos</section>
<p>Fuente: registro Security local. Los eventos pueden faltar por politicas de auditoria, retencion, limites de consulta o consulta desde otro equipo/DC. Revisar Notas_y_Cobertura.txt.</p>
</main></body></html>
"@
$Html | Out-File -LiteralPath $Reporte -Encoding UTF8
Progreso 98 'Escribiendo notas y cobertura'
$Notas = @("Equipo=$env:COMPUTERNAME","SO=$($Sistema.Caption)","Rol=$Rol","Desde=$($Inicio.ToString('yyyy-MM-dd HH:mm:ss'))","Hasta=$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))","Modo=$Modo","LimitePorEvento=$MaximoPorEvento","Eventos=$($Registros.Count)","TiempoSegundos=$([int]$Reloj.Elapsed.TotalSeconds)",'Origen=Security local','Advertencia: en dominios, consulte todos los DC relevantes; los grupos se listan con miembros directos, sin expansion anidada.','Advertencia: 4672 no demuestra membresia administrativa; eventos ausentes no prueban ausencia de actividad.')
$Notas += @($Limites.ToArray())
$Notas += @($Avisos.ToArray())
$Notas | Out-File -LiteralPath (Join-Path $Carpeta 'Notas_y_Cobertura.txt') -Encoding UTF8
Progreso 100 'Auditoria finalizada'
Write-Progress -Id 1 -Activity 'Auditoria de seguridad Windows' -Completed
Write-Host "`nAuditoria completada: $($Registros.Count) eventos en $([int]$Reloj.Elapsed.TotalSeconds)s" -ForegroundColor Green
Write-Host "Carpeta: $Carpeta"
Write-Host "Reporte HTML: $Reporte" -ForegroundColor Cyan
if ($Avisos.Count -gt 0) { Write-Warning "Se produjeron $($Avisos.Count) avisos. Revise Notas_y_Cobertura.txt" }
if (-not $SinPreguntas) {
    $Abrir = Read-Host 'Desea abrir el reporte HTML (S/N)'
    if ($Abrir -match '^[sSyY]') { Start-Process -FilePath $Reporte }
}
