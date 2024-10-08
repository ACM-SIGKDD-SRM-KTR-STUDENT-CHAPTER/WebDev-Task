import React from 'react';
import { Bar } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend } from 'chart.js';
import ChartDataLabels from 'chartjs-plugin-datalabels';

ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend, ChartDataLabels);

const AssessmentChart = () => {
  const data = {
    labels: ['Extroverted', 'Intuitive', 'Thinking', 'Judging', 'Assertive'],
    datasets: [
      {
        label: '',
        data: [50, 40, 70, 45, 55],
        backgroundColor: [
          '#7c73e6',
          '#7c73e6',
          '#7c73e6',
          '#7c73e6',
          '#7c73e6',
        ],
        borderWidth: 1,
        borderRadius: 8,
      },
    ],
  };
  const options = {
    responsive: true,
    maintainAspectRatio: true,
    aspectRatio: 2,
    scales: {
      y: {
        beginAtZero: true,
        max: 100,
        ticks: {
          stepSize: 20,
        },
      },
    },
    plugins: {
      datalabels: {
        display: true,
        color: 'black',
        anchor: 'end',
        align: 'start',
        formatter: (value, context) => {
          const topLabels = ['Introverted', 'Observant', 'Feeling', 'Prospecting', 'Terbulent'];
          return topLabels[context.dataIndex];
        },
      },
      legend: {
        display: false,
      },
    },
  };
  return (
    <div className="assessment" style={{ width: '60%', margin: 'auto', maxWidth: '800px', marginLeft: '3%' }}>
      <h3 style={{ textAlign: 'center', marginLeft: '150px' }}>Student Personality Assessment</h3>
      <Bar data={data} options={options} />
      <div style={{ position: 'absolute', width: '100%', top: '-50px', display: 'flex', justifyContent: 'space-between', paddingLeft: '5%', paddingRight: '5%' }}>
        <span style={{ textAlign: 'center', width: '20%' }}>Introverted</span>
        <span style={{ textAlign: 'center', width: '20%' }}>Observant</span>
        <span style={{ textAlign: 'center', width: '20%' }}>Feeling</span>
        <span style={{ textAlign: 'center', width: '20%' }}>Prospecting</span>
        <span style={{ textAlign: 'center', width: '20%' }}>Terbulent</span>
      </div>
    </div>
  );
};

export default AssessmentChart;