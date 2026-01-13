import pandas as pd
import glob
import os

def generate_summary_report():
    # Tìm tất cả các file csv bắt đầu bằng 'Report_' trong thư mục hiện tại
    file_pattern = "Report_*.csv"
    files = glob.glob(file_pattern)
    
    if not files:
        print("Không tìm thấy file báo cáo nào (Report_*.csv).")
        return

    summary_data = []

    print(f"Đang xử lý {len(files)} file...")

    for file_path in files:
        try:
            # Đọc file CSV
            df = pd.read_csv(file_path)
            
            # Lấy tên Rule từ tên file (bỏ tiền tố 'Report_' và hậu tố '.csv')
            rule_name = os.path.basename(file_path).replace('Report_', '').replace('.csv', '')
            
            # Đảm bảo cột Result tồn tại, chuyển về dạng chuỗi để xử lý
            if 'Result' not in df.columns:
                print(f"Cảnh báo: File {file_path} không có cột 'Result'. Bỏ qua.")
                continue
                
            results = df['Result'].astype(str)

            # Đếm số lượng theo trạng thái
            # 1. Triggered: Bắt đầu bằng chuỗi "Trigger:"
            triggered = results.apply(lambda x: x.startswith('Trigger:')).sum()
            
            # 2. Bypassed: Chính xác là "Bypass Target Rule"
            bypassed = results.apply(lambda x: x == 'Bypass Target Rule').sum()
            
            # 3. Errors: Chứa chuỗi "Log Error"
            errors = results.apply(lambda x: 'Log Error' in x).sum()
            
            # Tổng số test case
            total = len(df)
            
            # Tính tỷ lệ phát hiện (Detection Rate)
            # Công thức: Triggered / (Triggered + Bypassed)
            # (Loại bỏ các trường hợp lỗi Log Error khỏi mẫu số để công bằng hơn, hoặc dùng Total tùy nhu cầu)
            valid_samples = triggered + bypassed
            detection_rate = (triggered / valid_samples * 100) if valid_samples > 0 else 0.0
            
            summary_data.append({
                'Rule Name': rule_name,
                'Total Commands': total,
                'Triggered': triggered,
                'Bypassed': bypassed,
                'Errors': errors,
                'Detection Rate (%)': round(detection_rate, 2)
            })
            
        except Exception as e:
            print(f"Lỗi khi xử lý file {file_path}: {e}")

    if summary_data:
        # Tạo DataFrame tổng hợp
        summary_df = pd.DataFrame(summary_data)
        
        # Thêm dòng tổng cộng (TOTAL)
        total_row = {
            'Rule Name': 'TOTAL',
            'Total Commands': summary_df['Total Commands'].sum(),
            'Triggered': summary_df['Triggered'].sum(),
            'Bypassed': summary_df['Bypassed'].sum(),
            'Errors': summary_df['Errors'].sum(),
            'Detection Rate (%)': 0.0
        }
        # Tính lại % tổng
        valid_total = total_row['Triggered'] + total_row['Bypassed']
        total_row['Detection Rate (%)'] = round((total_row['Triggered'] / valid_total * 100), 2) if valid_total > 0 else 0.0
        
        summary_df = pd.concat([summary_df, pd.DataFrame([total_row])], ignore_index=True)

        # Xuất ra file CSV
        output_file = 'Summary_Report.csv'
        summary_df.to_csv(output_file, index=False)
        print(f"\nĐã tạo file tổng hợp thành công: {output_file}")
        print("-" * 30)
        print(summary_df.to_string())
    else:
        print("Không có dữ liệu để tổng hợp.")

if __name__ == "__main__":
    generate_summary_report()