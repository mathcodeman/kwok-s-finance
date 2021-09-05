from pandas_datareader import data
from pandas_datareader import data
from datetime import datetime,timedelta
from bokeh.plotting import figure
from bokeh.embed import components


def plot(symbol,days_from_now):
    start=datetime.now()-timedelta(days=days_from_now)
    end=datetime.now()
    df=data.DataReader(name=symbol,data_source="yahoo",start=start,end=end)
    date_increase=df.index[df.Close > df.Open]
    date_decrease=df.index[df.Close < df.Open]

    def inc_dec(c,o):
        if c > o:
            value="Increase"
        elif c < o:
            value="Decrease"
        else:
            value="Equal"
        return value

    df["Status"]=[inc_dec(c,o) for c,o in zip(df.Close,df.Open)]
    df["Middle"]=(df.Close+df.Open)/2
    df["Height"]=abs(df.Close-df.Open)

    p=figure(x_axis_type='datetime',width=1000,height=300,sizing_mode="scale_width")
    p.title="Candlestick Chart"
    p.grid.grid_line_alpha=0.3
    hours_12=12*60*60*1000
    p.segment(df.index,df.High,df.index,df.Low,color="black")
    p.rect(df.index[df.Status=="Increase"],df.Middle[df.Status=="Increase"],hours_12,df.Height[df.Status=="Increase"],
        fill_color="green",line_color="black")
    p.rect(df.index[df.Status=="Decrease"],df.Middle[df.Status=="Decrease"],hours_12,df.Height[df.Status=="Decrease"],
        fill_color="red",line_color="black")
    script1,div1= components(p)
    return (script1,div1)