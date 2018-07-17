from .analyzer import BrakemanAnalyzer
from .issues_data import issues_data

analyzers = {
    'brakeman' :
        {
            'name' : 'brakeman',
            'title' : 'Brakeman',
            'class' : BrakemanAnalyzer,
            'language' : 'ruby',
            'issues_data' : issues_data,
        },
}
