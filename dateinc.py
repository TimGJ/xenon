import datetime

startdate = datetime.date(2023, 3, 20)
window = datetime.timedelta(days=7)
enddate = datetime.date.today()
while (startdate + window) <= enddate:
    s = startdate.isoformat()
    e = (startdate + window).isoformat()
    startdate += window
    print(s,e)

